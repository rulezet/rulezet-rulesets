rule TTP_XOR_MULT_DOSStub_8fb8 {
  strings:
    $key_8fb8 = { db d0 [2] af c8 [2] e8 ca [2] af db [2] e1 d7 [2] ed dd [2] fa d6 [2] e1 98 [2] dc }

  condition:
    any of them
}