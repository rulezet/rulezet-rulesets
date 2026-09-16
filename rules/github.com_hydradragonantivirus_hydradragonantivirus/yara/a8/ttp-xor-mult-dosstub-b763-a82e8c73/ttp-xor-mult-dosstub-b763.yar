rule TTP_XOR_MULT_DOSStub_b763 {
  strings:
    $key_b763 = { e3 0b [2] 97 13 [2] d0 11 [2] 97 00 [2] d9 0c [2] d5 06 [2] c2 0d [2] d9 43 [2] e4 }

  condition:
    any of them
}