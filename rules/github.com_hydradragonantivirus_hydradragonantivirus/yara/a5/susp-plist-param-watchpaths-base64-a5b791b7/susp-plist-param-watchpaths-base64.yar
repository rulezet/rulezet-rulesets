rule SUSP_PList_Param_WatchPaths_base64 {
  strings:
    $ = "<key>WatchPaths</key>" base64 base64wide

  condition:
    all of them
}