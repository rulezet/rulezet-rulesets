rule TTP_XOR_MULT_DOSStub_1844 {
  strings:
    $key_1844 = { 4c 2c [2] 38 34 [2] 7f 36 [2] 38 27 [2] 76 2b [2] 7a 21 [2] 6d 2a [2] 76 64 [2] 4b }

  condition:
    any of them
}