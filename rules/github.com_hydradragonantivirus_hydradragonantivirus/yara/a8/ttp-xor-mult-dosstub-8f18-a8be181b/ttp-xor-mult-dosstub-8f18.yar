rule TTP_XOR_MULT_DOSStub_8f18 {
  strings:
    $key_8f18 = { db 70 [2] af 68 [2] e8 6a [2] af 7b [2] e1 77 [2] ed 7d [2] fa 76 [2] e1 38 [2] dc }

  condition:
    any of them
}