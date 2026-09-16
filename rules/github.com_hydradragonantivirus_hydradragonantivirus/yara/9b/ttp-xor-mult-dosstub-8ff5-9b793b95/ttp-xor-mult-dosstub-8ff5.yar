rule TTP_XOR_MULT_DOSStub_8ff5 {
  strings:
    $key_8ff5 = { db 9d [2] af 85 [2] e8 87 [2] af 96 [2] e1 9a [2] ed 90 [2] fa 9b [2] e1 d5 [2] dc }

  condition:
    any of them
}