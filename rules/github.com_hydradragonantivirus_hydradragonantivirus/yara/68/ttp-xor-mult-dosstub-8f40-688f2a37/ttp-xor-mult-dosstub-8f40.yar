rule TTP_XOR_MULT_DOSStub_8f40 {
  strings:
    $key_8f40 = { db 28 [2] af 30 [2] e8 32 [2] af 23 [2] e1 2f [2] ed 25 [2] fa 2e [2] e1 60 [2] dc }

  condition:
    any of them
}