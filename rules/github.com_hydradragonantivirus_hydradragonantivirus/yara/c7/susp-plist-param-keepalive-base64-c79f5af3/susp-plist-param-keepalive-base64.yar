rule SUSP_PList_Param_KeepAlive_base64 {
  strings:
    $ = "<key>KeepAlive</key>" base64 base64wide

  condition:
    all of them
}