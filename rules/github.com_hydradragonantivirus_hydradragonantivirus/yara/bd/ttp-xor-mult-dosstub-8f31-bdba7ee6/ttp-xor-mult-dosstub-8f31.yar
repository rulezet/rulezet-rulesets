rule TTP_XOR_MULT_DOSStub_8f31 {
  strings:
    $key_8f31 = { db 59 [2] af 41 [2] e8 43 [2] af 52 [2] e1 5e [2] ed 54 [2] fa 5f [2] e1 11 [2] dc }

  condition:
    any of them
}