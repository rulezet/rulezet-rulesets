rule SUSP_PList_Param_StartCalendarInterval_xor {
  strings:
    $ = "<key>StartCalendarInterval</key>" xor(0x01-0xff)

  condition:
    all of them
}