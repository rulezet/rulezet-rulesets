rule TTP_XOR_MULT_DOSStub_8fe6 {
  strings:
    $key_8fe6 = { db 8e [2] af 96 [2] e8 94 [2] af 85 [2] e1 89 [2] ed 83 [2] fa 88 [2] e1 c6 [2] dc }

  condition:
    any of them
}