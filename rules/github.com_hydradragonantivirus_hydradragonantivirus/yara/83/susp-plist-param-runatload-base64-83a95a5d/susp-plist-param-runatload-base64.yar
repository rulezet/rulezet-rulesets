rule SUSP_PList_Param_RunAtLoad_base64 {
  strings:
    $ = "<key>RunAtLoad</key>" base64 base64wide

  condition:
    all of them
}