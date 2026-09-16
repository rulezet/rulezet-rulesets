rule TTP_XOR_MULT_DOSStub_8f08 {
  strings:
    $key_8f08 = { db 60 [2] af 78 [2] e8 7a [2] af 6b [2] e1 67 [2] ed 6d [2] fa 66 [2] e1 28 [2] dc }

  condition:
    any of them
}