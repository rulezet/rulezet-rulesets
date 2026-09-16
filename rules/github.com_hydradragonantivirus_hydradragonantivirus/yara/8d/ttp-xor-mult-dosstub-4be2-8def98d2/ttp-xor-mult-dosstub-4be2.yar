rule TTP_XOR_MULT_DOSStub_4be2 {
  strings:
    $key_4be2 = { 1f 8a [2] 6b 92 [2] 2c 90 [2] 6b 81 [2] 25 8d [2] 29 87 [2] 3e 8c [2] 25 c2 [2] 18 }

  condition:
    any of them
}