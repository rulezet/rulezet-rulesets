rule TTP_XOR_MULT_DOSStub_8f77 {
  strings:
    $key_8f77 = { db 1f [2] af 07 [2] e8 05 [2] af 14 [2] e1 18 [2] ed 12 [2] fa 19 [2] e1 57 [2] dc }

  condition:
    any of them
}