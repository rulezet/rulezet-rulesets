rule INFO_PList_Param_OtherJobEnabled {
  strings:
    $ = "<key>OtherJobEnabled</key>" ascii wide

  condition:
    all of them
}