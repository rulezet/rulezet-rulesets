rule TTP_XOR_MULT_DOSStub_d9d9 {
  strings:
    $key_d9d9 = { 8d b1 [2] f9 a9 [2] be ab [2] f9 ba [2] b7 b6 [2] bb bc [2] ac b7 [2] b7 f9 [2] 8a }

  condition:
    any of them
}