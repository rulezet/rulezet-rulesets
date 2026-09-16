rule TTP_XOR_MULT_DOSStub_8f44 {
  strings:
    $key_8f44 = { db 2c [2] af 34 [2] e8 36 [2] af 27 [2] e1 2b [2] ed 21 [2] fa 2a [2] e1 64 [2] dc }

  condition:
    any of them
}