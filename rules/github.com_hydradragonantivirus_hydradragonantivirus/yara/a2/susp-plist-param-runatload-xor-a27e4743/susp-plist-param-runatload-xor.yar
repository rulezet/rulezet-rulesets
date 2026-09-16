rule SUSP_PList_Param_RunAtLoad_xor {
  strings:
    $ = "<key>RunAtLoad</key>" xor(0x01-0xff)

  condition:
    all of them
}