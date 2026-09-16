rule TTP_XOR_MULT_DOSStub_b317 {
  strings:
    $key_b317 = { e7 7f [2] 93 67 [2] d4 65 [2] 93 74 [2] dd 78 [2] d1 72 [2] c6 79 [2] dd 37 [2] e0 }

  condition:
    any of them
}