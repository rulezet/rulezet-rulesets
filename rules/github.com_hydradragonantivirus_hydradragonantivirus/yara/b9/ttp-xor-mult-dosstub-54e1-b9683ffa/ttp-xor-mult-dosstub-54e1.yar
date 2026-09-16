rule TTP_XOR_MULT_DOSStub_54e1 {
  strings:
    $key_54e1 = { 00 89 [2] 74 91 [2] 33 93 [2] 74 82 [2] 3a 8e [2] 36 84 [2] 21 8f [2] 3a c1 [2] 07 }

  condition:
    any of them
}