rule TTP_XOR_MULT_DOSStub_e627 {
  strings:
    $key_e627 = { b2 4f [2] c6 57 [2] 81 55 [2] c6 44 [2] 88 48 [2] 84 42 [2] 93 49 [2] 88 07 [2] b5 }

  condition:
    any of them
}