rule SUSP_PList_Param_RootDirectory_xor {
  strings:
    $ = "<key>RootDirectory</key>" xor(0x01-0xff)

  condition:
    all of them
}