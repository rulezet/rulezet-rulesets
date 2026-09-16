rule TTP_XOR_MULT_DOSStub_8f14 {
  strings:
    $key_8f14 = { db 7c [2] af 64 [2] e8 66 [2] af 77 [2] e1 7b [2] ed 71 [2] fa 7a [2] e1 34 [2] dc }

  condition:
    any of them
}