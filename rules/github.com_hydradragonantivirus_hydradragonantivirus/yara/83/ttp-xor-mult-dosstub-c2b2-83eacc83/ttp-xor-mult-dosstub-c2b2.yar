rule TTP_XOR_MULT_DOSStub_c2b2 {
  strings:
    $key_c2b2 = { 96 da [2] e2 c2 [2] a5 c0 [2] e2 d1 [2] ac dd [2] a0 d7 [2] b7 dc [2] ac 92 [2] 91 }

  condition:
    any of them
}