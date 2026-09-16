rule TTP_XOR_MULT_DOSStub_d9be {
  strings:
    $key_d9be = { 8d d6 [2] f9 ce [2] be cc [2] f9 dd [2] b7 d1 [2] bb db [2] ac d0 [2] b7 9e [2] 8a }

  condition:
    any of them
}