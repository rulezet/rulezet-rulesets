rule TTP_XOR_MULT_DOSStub_8f66 {
  strings:
    $key_8f66 = { db 0e [2] af 16 [2] e8 14 [2] af 05 [2] e1 09 [2] ed 03 [2] fa 08 [2] e1 46 [2] dc }

  condition:
    any of them
}