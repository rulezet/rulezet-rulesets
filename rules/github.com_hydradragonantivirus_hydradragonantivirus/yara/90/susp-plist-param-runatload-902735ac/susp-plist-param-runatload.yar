rule SUSP_PList_Param_RunAtLoad {
  strings:
    $ = "<key>RunAtLoad</key>" ascii wide

  condition:
    all of them
}