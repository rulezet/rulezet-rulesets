rule TTP_XOR_MULT_DOSStub_b737 {
  strings:
    $key_b737 = { e3 5f [2] 97 47 [2] d0 45 [2] 97 54 [2] d9 58 [2] d5 52 [2] c2 59 [2] d9 17 [2] e4 }

  condition:
    any of them
}