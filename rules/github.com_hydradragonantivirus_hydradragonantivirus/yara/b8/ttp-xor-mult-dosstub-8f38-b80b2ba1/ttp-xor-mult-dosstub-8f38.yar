rule TTP_XOR_MULT_DOSStub_8f38 {
  strings:
    $key_8f38 = { db 50 [2] af 48 [2] e8 4a [2] af 5b [2] e1 57 [2] ed 5d [2] fa 56 [2] e1 18 [2] dc }

  condition:
    any of them
}