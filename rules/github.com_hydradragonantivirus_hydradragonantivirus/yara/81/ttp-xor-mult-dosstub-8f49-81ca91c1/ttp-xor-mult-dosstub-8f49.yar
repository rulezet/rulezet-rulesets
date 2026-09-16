rule TTP_XOR_MULT_DOSStub_8f49 {
  strings:
    $key_8f49 = { db 21 [2] af 39 [2] e8 3b [2] af 2a [2] e1 26 [2] ed 2c [2] fa 27 [2] e1 69 [2] dc }

  condition:
    any of them
}