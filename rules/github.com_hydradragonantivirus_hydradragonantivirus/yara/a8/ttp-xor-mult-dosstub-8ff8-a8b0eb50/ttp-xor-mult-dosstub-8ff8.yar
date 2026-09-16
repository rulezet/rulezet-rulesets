rule TTP_XOR_MULT_DOSStub_8ff8 {
  strings:
    $key_8ff8 = { db 90 [2] af 88 [2] e8 8a [2] af 9b [2] e1 97 [2] ed 9d [2] fa 96 [2] e1 d8 [2] dc }

  condition:
    any of them
}