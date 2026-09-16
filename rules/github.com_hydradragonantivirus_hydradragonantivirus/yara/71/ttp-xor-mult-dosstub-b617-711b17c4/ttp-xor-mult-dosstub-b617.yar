rule TTP_XOR_MULT_DOSStub_b617 {
  strings:
    $key_b617 = { e2 7f [2] 96 67 [2] d1 65 [2] 96 74 [2] d8 78 [2] d4 72 [2] c3 79 [2] d8 37 [2] e5 }

  condition:
    any of them
}