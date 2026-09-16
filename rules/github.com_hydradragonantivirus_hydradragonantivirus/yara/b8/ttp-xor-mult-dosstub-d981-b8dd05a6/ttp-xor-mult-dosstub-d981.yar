rule TTP_XOR_MULT_DOSStub_d981 {
  strings:
    $key_d981 = { 8d e9 [2] f9 f1 [2] be f3 [2] f9 e2 [2] b7 ee [2] bb e4 [2] ac ef [2] b7 a1 [2] 8a }

  condition:
    any of them
}