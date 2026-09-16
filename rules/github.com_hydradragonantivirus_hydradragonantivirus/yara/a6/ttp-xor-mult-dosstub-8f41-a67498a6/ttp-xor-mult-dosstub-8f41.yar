rule TTP_XOR_MULT_DOSStub_8f41 {
  strings:
    $key_8f41 = { db 29 [2] af 31 [2] e8 33 [2] af 22 [2] e1 2e [2] ed 24 [2] fa 2f [2] e1 61 [2] dc }

  condition:
    any of them
}