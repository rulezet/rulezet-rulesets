rule TTP_XOR_MULT_DOSStub_4af1 {
  strings:
    $key_4af1 = { 1e 99 [2] 6a 81 [2] 2d 83 [2] 6a 92 [2] 24 9e [2] 28 94 [2] 3f 9f [2] 24 d1 [2] 19 }

  condition:
    any of them
}