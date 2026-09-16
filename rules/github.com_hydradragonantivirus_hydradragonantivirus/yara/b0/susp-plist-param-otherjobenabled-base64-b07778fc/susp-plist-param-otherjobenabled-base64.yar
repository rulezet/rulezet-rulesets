rule SUSP_PList_Param_OtherJobEnabled_base64 {
  strings:
    $ = "<key>OtherJobEnabled</key>" base64 base64wide

  condition:
    all of them
}