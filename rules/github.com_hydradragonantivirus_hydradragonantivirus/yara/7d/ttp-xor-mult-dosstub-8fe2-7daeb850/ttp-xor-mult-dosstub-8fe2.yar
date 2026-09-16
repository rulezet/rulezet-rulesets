rule TTP_XOR_MULT_DOSStub_8fe2 {
  strings:
    $key_8fe2 = { db 8a [2] af 92 [2] e8 90 [2] af 81 [2] e1 8d [2] ed 87 [2] fa 8c [2] e1 c2 [2] dc }

  condition:
    any of them
}