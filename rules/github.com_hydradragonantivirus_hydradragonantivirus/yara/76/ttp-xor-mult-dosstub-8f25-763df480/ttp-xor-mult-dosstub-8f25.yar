rule TTP_XOR_MULT_DOSStub_8f25 {
  strings:
    $key_8f25 = { db 4d [2] af 55 [2] e8 57 [2] af 46 [2] e1 4a [2] ed 40 [2] fa 4b [2] e1 05 [2] dc }

  condition:
    any of them
}