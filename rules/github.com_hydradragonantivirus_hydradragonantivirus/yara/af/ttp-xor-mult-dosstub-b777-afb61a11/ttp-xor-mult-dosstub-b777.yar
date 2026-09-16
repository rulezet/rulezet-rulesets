rule TTP_XOR_MULT_DOSStub_b777 {
  strings:
    $key_b777 = { e3 1f [2] 97 07 [2] d0 05 [2] 97 14 [2] d9 18 [2] d5 12 [2] c2 19 [2] d9 57 [2] e4 }

  condition:
    any of them
}