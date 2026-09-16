rule TTP_XOR_MULT_DOSStub_b767 {
  strings:
    $key_b767 = { e3 0f [2] 97 17 [2] d0 15 [2] 97 04 [2] d9 08 [2] d5 02 [2] c2 09 [2] d9 47 [2] e4 }

  condition:
    any of them
}