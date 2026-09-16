rule TTP_XOR_MULT_DOSStub_8f74 {
  strings:
    $key_8f74 = { db 1c [2] af 04 [2] e8 06 [2] af 17 [2] e1 1b [2] ed 11 [2] fa 1a [2] e1 54 [2] dc }

  condition:
    any of them
}