rule TTP_XOR_MULT_DOSStub_c2be {
  strings:
    $key_c2be = { 96 d6 [2] e2 ce [2] a5 cc [2] e2 dd [2] ac d1 [2] a0 db [2] b7 d0 [2] ac 9e [2] 91 }

  condition:
    any of them
}