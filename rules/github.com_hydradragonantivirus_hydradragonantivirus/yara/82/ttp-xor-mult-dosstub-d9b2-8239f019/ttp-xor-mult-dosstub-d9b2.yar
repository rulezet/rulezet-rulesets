rule TTP_XOR_MULT_DOSStub_d9b2 {
  strings:
    $key_d9b2 = { 8d da [2] f9 c2 [2] be c0 [2] f9 d1 [2] b7 dd [2] bb d7 [2] ac dc [2] b7 92 [2] 8a }

  condition:
    any of them
}