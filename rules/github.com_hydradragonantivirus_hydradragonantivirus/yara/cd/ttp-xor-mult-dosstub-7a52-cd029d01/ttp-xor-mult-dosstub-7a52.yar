rule TTP_XOR_MULT_DOSStub_7a52 {
  strings:
    $key_7a52 = { 2e 3a [2] 5a 22 [2] 1d 20 [2] 5a 31 [2] 14 3d [2] 18 37 [2] 0f 3c [2] 14 72 [2] 29 }

  condition:
    any of them
}