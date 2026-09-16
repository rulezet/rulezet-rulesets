rule TTP_XOR_MULT_DOSStub_92f7 {
  strings:
    $key_92f7 = { c6 9f [2] b2 87 [2] f5 85 [2] b2 94 [2] fc 98 [2] f0 92 [2] e7 99 [2] fc d7 [2] c1 }

  condition:
    any of them
}