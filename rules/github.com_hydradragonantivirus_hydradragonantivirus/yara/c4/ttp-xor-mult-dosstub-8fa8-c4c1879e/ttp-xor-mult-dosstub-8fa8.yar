rule TTP_XOR_MULT_DOSStub_8fa8 {
  strings:
    $key_8fa8 = { db c0 [2] af d8 [2] e8 da [2] af cb [2] e1 c7 [2] ed cd [2] fa c6 [2] e1 88 [2] dc }

  condition:
    any of them
}