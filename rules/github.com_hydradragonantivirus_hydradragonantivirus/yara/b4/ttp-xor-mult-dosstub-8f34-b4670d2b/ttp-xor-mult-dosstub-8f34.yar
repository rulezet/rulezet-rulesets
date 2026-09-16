rule TTP_XOR_MULT_DOSStub_8f34 {
  strings:
    $key_8f34 = { db 5c [2] af 44 [2] e8 46 [2] af 57 [2] e1 5b [2] ed 51 [2] fa 5a [2] e1 14 [2] dc }

  condition:
    any of them
}