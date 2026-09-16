rule INFO_PList_Param_StartCalendarInterval {
  strings:
    $ = "<key>StartCalendarInterval</key>" ascii wide

  condition:
    all of them
}