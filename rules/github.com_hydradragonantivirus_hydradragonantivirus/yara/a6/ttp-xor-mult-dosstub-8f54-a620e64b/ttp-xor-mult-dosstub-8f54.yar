rule TTP_XOR_MULT_DOSStub_8f54 {
  strings:
    $key_8f54 = { db 3c [2] af 24 [2] e8 26 [2] af 37 [2] e1 3b [2] ed 31 [2] fa 3a [2] e1 74 [2] dc }

  condition:
    any of them
}