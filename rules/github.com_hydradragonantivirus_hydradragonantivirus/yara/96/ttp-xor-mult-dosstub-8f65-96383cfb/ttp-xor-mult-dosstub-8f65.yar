rule TTP_XOR_MULT_DOSStub_8f65 {
  strings:
    $key_8f65 = { db 0d [2] af 15 [2] e8 17 [2] af 06 [2] e1 0a [2] ed 00 [2] fa 0b [2] e1 45 [2] dc }

  condition:
    any of them
}