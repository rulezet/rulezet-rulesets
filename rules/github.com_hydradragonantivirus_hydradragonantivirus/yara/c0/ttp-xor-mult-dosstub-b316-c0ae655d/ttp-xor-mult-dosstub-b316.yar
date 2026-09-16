rule TTP_XOR_MULT_DOSStub_b316 {
  strings:
    $key_b316 = { e7 7e [2] 93 66 [2] d4 64 [2] 93 75 [2] dd 79 [2] d1 73 [2] c6 78 [2] dd 36 [2] e0 }

  condition:
    any of them
}