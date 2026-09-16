rule TTP_XOR_MULT_DOSStub_f1b8 {
  strings:
    $key_f1b8 = { a5 d0 [2] d1 c8 [2] 96 ca [2] d1 db [2] 9f d7 [2] 93 dd [2] 84 d6 [2] 9f 98 [2] a2 }

  condition:
    any of them
}