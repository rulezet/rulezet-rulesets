rule TTP_XOR_MULT_DOSStub_b7e4 {
  strings:
    $key_b7e4 = { e3 8c [2] 97 94 [2] d0 96 [2] 97 87 [2] d9 8b [2] d5 81 [2] c2 8a [2] d9 c4 [2] e4 }

  condition:
    any of them
}