rule TTP_XOR_MULT_DOSStub_d9a9 {
  strings:
    $key_d9a9 = { 8d c1 [2] f9 d9 [2] be db [2] f9 ca [2] b7 c6 [2] bb cc [2] ac c7 [2] b7 89 [2] 8a }

  condition:
    any of them
}