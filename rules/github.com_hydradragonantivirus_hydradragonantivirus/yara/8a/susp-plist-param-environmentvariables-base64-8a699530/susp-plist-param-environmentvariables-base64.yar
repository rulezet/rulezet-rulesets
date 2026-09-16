rule SUSP_PList_Param_EnvironmentVariables_base64 {
  strings:
    $ = "<key>EnvironmentVariables</key>" base64 base64wide

  condition:
    all of them
}