rule TTP_XOR_MULT_DOSStub_8f76 {
  strings:
    $key_8f76 = { db 1e [2] af 06 [2] e8 04 [2] af 15 [2] e1 19 [2] ed 13 [2] fa 18 [2] e1 56 [2] dc }

  condition:
    any of them
}