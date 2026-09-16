rule TTP_XOR_MULT_DOSStub_8f68 {
  strings:
    $key_8f68 = { db 00 [2] af 18 [2] e8 1a [2] af 0b [2] e1 07 [2] ed 0d [2] fa 06 [2] e1 48 [2] dc }

  condition:
    any of them
}