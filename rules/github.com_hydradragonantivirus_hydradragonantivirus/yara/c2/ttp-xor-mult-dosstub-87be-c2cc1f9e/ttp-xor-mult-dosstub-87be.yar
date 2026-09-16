rule TTP_XOR_MULT_DOSStub_87be {
  strings:
    $key_87be = { d3 d6 [2] a7 ce [2] e0 cc [2] a7 dd [2] e9 d1 [2] e5 db [2] f2 d0 [2] e9 9e [2] d4 }

  condition:
    any of them
}