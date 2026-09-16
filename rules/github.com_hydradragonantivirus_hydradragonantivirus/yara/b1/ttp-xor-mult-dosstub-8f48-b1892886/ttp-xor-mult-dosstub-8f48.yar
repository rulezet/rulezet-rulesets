rule TTP_XOR_MULT_DOSStub_8f48 {
  strings:
    $key_8f48 = { db 20 [2] af 38 [2] e8 3a [2] af 2b [2] e1 27 [2] ed 2d [2] fa 26 [2] e1 68 [2] dc }

  condition:
    any of them
}