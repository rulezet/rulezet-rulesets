rule INFO_PList_Param_QueueDirectories {
  strings:
    $ = "<key>QueueDirectories</key>" ascii wide

  condition:
    all of them
}