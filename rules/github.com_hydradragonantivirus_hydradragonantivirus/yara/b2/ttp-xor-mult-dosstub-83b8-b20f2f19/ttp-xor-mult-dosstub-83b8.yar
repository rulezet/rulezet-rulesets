rule TTP_XOR_MULT_DOSStub_83b8 {
  strings:
    $key_83b8 = { d7 d0 [2] a3 c8 [2] e4 ca [2] a3 db [2] ed d7 [2] e1 dd [2] f6 d6 [2] ed 98 [2] d0 }

  condition:
    any of them
}