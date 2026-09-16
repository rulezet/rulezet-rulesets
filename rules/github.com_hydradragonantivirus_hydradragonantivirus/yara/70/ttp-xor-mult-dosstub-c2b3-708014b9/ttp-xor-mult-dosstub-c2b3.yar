rule TTP_XOR_MULT_DOSStub_c2b3 {
  strings:
    $key_c2b3 = { 96 db [2] e2 c3 [2] a5 c1 [2] e2 d0 [2] ac dc [2] a0 d6 [2] b7 dd [2] ac 93 [2] 91 }

  condition:
    any of them
}