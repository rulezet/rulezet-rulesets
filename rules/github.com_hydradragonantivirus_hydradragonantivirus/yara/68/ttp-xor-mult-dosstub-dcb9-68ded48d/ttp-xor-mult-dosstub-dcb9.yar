rule TTP_XOR_MULT_DOSStub_dcb9 {
  strings:
    $key_dcb9 = { 88 d1 [2] fc c9 [2] bb cb [2] fc da [2] b2 d6 [2] be dc [2] a9 d7 [2] b2 99 [2] 8f }

  condition:
    any of them
}