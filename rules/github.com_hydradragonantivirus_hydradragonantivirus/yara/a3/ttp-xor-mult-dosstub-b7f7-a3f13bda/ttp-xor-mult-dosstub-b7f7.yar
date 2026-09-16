rule TTP_XOR_MULT_DOSStub_b7f7 {
  strings:
    $key_b7f7 = { e3 9f [2] 97 87 [2] d0 85 [2] 97 94 [2] d9 98 [2] d5 92 [2] c2 99 [2] d9 d7 [2] e4 }

  condition:
    any of them
}