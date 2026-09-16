rule TTP_XOR_MULT_DOSStub_0be2 {
  strings:
    $key_0be2 = { 5f 8a [2] 2b 92 [2] 6c 90 [2] 2b 81 [2] 65 8d [2] 69 87 [2] 7e 8c [2] 65 c2 [2] 58 }

  condition:
    any of them
}