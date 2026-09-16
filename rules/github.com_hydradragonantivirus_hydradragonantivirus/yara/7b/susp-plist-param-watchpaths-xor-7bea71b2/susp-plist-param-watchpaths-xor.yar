rule SUSP_PList_Param_WatchPaths_xor {
  strings:
    $ = "<key>WatchPaths</key>" xor(0x01-0xff)

  condition:
    all of them
}