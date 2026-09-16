rule TTP_XOR_MULT_DOSStub_2bb1 {
  strings:
    $key_2bb1 = { 7f d9 [2] 0b c1 [2] 4c c3 [2] 0b d2 [2] 45 de [2] 49 d4 [2] 5e df [2] 45 91 [2] 78 }

  condition:
    any of them
}