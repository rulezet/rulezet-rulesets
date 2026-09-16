rule TTP_XOR_MULT_DOSStub_d9b4 {
  strings:
    $key_d9b4 = { 8d dc [2] f9 c4 [2] be c6 [2] f9 d7 [2] b7 db [2] bb d1 [2] ac da [2] b7 94 [2] 8a }

  condition:
    any of them
}