rule TTP_XOR_MULT_DOSStub_d8b2 {
  strings:
    $key_d8b2 = { 8c da [2] f8 c2 [2] bf c0 [2] f8 d1 [2] b6 dd [2] ba d7 [2] ad dc [2] b6 92 [2] 8b }

  condition:
    any of them
}