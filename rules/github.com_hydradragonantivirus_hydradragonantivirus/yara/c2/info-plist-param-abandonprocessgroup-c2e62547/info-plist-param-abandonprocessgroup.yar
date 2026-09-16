rule INFO_PList_Param_AbandonProcessGroup {
  strings:
    $ = "<key>AbandonProcessGroup</key>" ascii wide

  condition:
    all of them
}