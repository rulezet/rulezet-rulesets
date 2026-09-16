rule SUSP_PList_Param_AbandonProcessGroup_xor {
  strings:
    $ = "<key>AbandonProcessGroup</key>" xor(0x01-0xff)

  condition:
    all of them
}