rule TTP_XOR_MULT_DOSStub_8fe4 {
  strings:
    $key_8fe4 = { db 8c [2] af 94 [2] e8 96 [2] af 87 [2] e1 8b [2] ed 81 [2] fa 8a [2] e1 c4 [2] dc }

  condition:
    any of them
}