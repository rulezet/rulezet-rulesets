rule TTP_XOR_MULT_DOSStub_8fe7 {
  strings:
    $key_8fe7 = { db 8f [2] af 97 [2] e8 95 [2] af 84 [2] e1 88 [2] ed 82 [2] fa 89 [2] e1 c7 [2] dc }

  condition:
    any of them
}