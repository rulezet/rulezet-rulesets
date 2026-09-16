rule TTP_XOR_MULT_DOSStub_b707 {
  strings:
    $key_b707 = { e3 6f [2] 97 77 [2] d0 75 [2] 97 64 [2] d9 68 [2] d5 62 [2] c2 69 [2] d9 27 [2] e4 }

  condition:
    any of them
}