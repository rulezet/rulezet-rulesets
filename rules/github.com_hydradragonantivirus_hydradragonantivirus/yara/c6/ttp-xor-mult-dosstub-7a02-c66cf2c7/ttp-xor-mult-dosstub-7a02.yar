rule TTP_XOR_MULT_DOSStub_7a02 {
  strings:
    $key_7a02 = { 2e 6a [2] 5a 72 [2] 1d 70 [2] 5a 61 [2] 14 6d [2] 18 67 [2] 0f 6c [2] 14 22 [2] 29 }

  condition:
    any of them
}