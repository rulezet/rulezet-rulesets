rule TTP_XOR_MULT_DOSStub_8fa9 {
  strings:
    $key_8fa9 = { db c1 [2] af d9 [2] e8 db [2] af ca [2] e1 c6 [2] ed cc [2] fa c7 [2] e1 89 [2] dc }

  condition:
    any of them
}