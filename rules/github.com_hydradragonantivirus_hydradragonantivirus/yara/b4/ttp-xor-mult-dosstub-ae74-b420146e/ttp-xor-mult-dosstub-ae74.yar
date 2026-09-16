rule TTP_XOR_MULT_DOSStub_ae74 {
  strings:
    $key_ae74 = { fa 1c [2] 8e 04 [2] c9 06 [2] 8e 17 [2] c0 1b [2] cc 11 [2] db 1a [2] c0 54 [2] fd }

  condition:
    any of them
}