rule TTP_XOR_MULT_DOSStub_8fe5 {
  strings:
    $key_8fe5 = { db 8d [2] af 95 [2] e8 97 [2] af 86 [2] e1 8a [2] ed 80 [2] fa 8b [2] e1 c5 [2] dc }

  condition:
    any of them
}