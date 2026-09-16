rule SUSP_PList_Param_KeepAlive_xor {
  strings:
    $ = "<key>KeepAlive</key>" xor(0x01-0xff)

  condition:
    all of them
}