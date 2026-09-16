rule INFO_PList_Param_StartOnMount {
  strings:
    $ = "<key>StartOnMount</key>" ascii wide

  condition:
    all of them
}