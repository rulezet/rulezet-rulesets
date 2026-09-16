rule INFO_PList_Param_EnvironmentVariables {
  strings:
    $ = "<key>EnvironmentVariables</key>" ascii wide

  condition:
    all of them
}