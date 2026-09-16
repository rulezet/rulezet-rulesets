rule TTP_XOR_MULT_DOSStub_8fe8 {
  strings:
    $key_8fe8 = { db 80 [2] af 98 [2] e8 9a [2] af 8b [2] e1 87 [2] ed 8d [2] fa 86 [2] e1 c8 [2] dc }

  condition:
    any of them
}