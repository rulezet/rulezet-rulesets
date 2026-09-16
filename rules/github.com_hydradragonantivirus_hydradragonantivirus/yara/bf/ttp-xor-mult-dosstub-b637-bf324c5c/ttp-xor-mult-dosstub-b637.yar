rule TTP_XOR_MULT_DOSStub_b637 {
  strings:
    $key_b637 = { e2 5f [2] 96 47 [2] d1 45 [2] 96 54 [2] d8 58 [2] d4 52 [2] c3 59 [2] d8 17 [2] e5 }

  condition:
    any of them
}