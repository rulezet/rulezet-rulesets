rule TTP_XOR_MULT_DOSStub_4af7 {
  strings:
    $key_4af7 = { 1e 9f [2] 6a 87 [2] 2d 85 [2] 6a 94 [2] 24 98 [2] 28 92 [2] 3f 99 [2] 24 d7 [2] 19 }

  condition:
    any of them
}