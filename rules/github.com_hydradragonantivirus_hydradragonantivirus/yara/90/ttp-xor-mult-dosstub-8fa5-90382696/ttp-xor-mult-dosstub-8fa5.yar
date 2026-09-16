rule TTP_XOR_MULT_DOSStub_8fa5 {
  strings:
    $key_8fa5 = { db cd [2] af d5 [2] e8 d7 [2] af c6 [2] e1 ca [2] ed c0 [2] fa cb [2] e1 85 [2] dc }

  condition:
    any of them
}