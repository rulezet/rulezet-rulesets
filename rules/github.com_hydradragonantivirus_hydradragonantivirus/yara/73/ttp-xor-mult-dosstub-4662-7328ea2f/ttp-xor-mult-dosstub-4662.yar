rule TTP_XOR_MULT_DOSStub_4662 {
  strings:
    $key_4662 = { 12 0a [2] 66 12 [2] 21 10 [2] 66 01 [2] 28 0d [2] 24 07 [2] 33 0c [2] 28 42 [2] 15 }

  condition:
    any of them
}