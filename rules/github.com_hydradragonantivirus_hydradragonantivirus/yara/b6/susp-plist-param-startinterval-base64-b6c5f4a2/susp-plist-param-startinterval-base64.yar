rule SUSP_PList_Param_StartInterval_base64 {
  strings:
    $ = "<key>StartInterval</key>" base64 base64wide

  condition:
    all of them
}