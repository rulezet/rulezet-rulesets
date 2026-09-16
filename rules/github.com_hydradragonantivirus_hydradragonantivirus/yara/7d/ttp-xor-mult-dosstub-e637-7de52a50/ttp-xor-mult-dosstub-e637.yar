rule TTP_XOR_MULT_DOSStub_e637 {
  strings:
    $key_e637 = { b2 5f [2] c6 47 [2] 81 45 [2] c6 54 [2] 88 58 [2] 84 52 [2] 93 59 [2] 88 17 [2] b5 }

  condition:
    any of them
}