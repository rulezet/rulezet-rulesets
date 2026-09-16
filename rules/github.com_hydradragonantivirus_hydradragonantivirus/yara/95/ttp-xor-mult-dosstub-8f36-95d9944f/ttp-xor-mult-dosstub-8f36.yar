rule TTP_XOR_MULT_DOSStub_8f36 {
  strings:
    $key_8f36 = { db 5e [2] af 46 [2] e8 44 [2] af 55 [2] e1 59 [2] ed 53 [2] fa 58 [2] e1 16 [2] dc }

  condition:
    any of them
}