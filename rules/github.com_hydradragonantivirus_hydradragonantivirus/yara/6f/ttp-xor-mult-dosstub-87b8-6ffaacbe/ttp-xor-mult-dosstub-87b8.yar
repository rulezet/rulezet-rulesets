rule TTP_XOR_MULT_DOSStub_87b8 {
  strings:
    $key_87b8 = { d3 d0 [2] a7 c8 [2] e0 ca [2] a7 db [2] e9 d7 [2] e5 dd [2] f2 d6 [2] e9 98 [2] d4 }

  condition:
    any of them
}