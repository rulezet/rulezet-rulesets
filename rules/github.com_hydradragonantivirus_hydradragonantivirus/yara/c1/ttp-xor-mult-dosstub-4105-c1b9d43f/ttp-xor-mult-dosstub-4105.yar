rule TTP_XOR_MULT_DOSStub_4105 {
  strings:
    $key_4105 = { 15 6d [2] 61 75 [2] 26 77 [2] 61 66 [2] 2f 6a [2] 23 60 [2] 34 6b [2] 2f 25 [2] 12 }

  condition:
    any of them
}