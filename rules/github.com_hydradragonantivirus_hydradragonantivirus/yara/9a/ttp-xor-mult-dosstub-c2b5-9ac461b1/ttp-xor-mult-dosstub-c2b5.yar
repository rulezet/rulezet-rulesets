rule TTP_XOR_MULT_DOSStub_c2b5 {
  strings:
    $key_c2b5 = { 96 dd [2] e2 c5 [2] a5 c7 [2] e2 d6 [2] ac da [2] a0 d0 [2] b7 db [2] ac 95 [2] 91 }

  condition:
    any of them
}