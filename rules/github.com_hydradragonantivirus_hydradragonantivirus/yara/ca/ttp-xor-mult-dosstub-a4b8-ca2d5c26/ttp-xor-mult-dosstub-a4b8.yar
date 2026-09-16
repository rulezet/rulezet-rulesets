rule TTP_XOR_MULT_DOSStub_a4b8 {
  strings:
    $key_a4b8 = { f0 d0 [2] 84 c8 [2] c3 ca [2] 84 db [2] ca d7 [2] c6 dd [2] d1 d6 [2] ca 98 [2] f7 }

  condition:
    any of them
}