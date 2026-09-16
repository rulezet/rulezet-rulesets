rule SUSP_PList_Param_KeepAlive {
  strings:
    $ = "<key>KeepAlive</key>" ascii wide

  condition:
    all of them
}