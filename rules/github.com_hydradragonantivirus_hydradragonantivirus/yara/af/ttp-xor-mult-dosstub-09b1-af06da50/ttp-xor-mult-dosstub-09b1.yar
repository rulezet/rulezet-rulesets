rule TTP_XOR_MULT_DOSStub_09b1 {
  strings:
    $key_09b1 = { 5d d9 [2] 29 c1 [2] 6e c3 [2] 29 d2 [2] 67 de [2] 6b d4 [2] 7c df [2] 67 91 [2] 5a }

  condition:
    any of them
}