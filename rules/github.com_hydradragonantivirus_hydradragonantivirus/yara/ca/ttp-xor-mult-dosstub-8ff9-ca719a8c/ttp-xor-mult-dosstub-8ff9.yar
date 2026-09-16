rule TTP_XOR_MULT_DOSStub_8ff9 {
  strings:
    $key_8ff9 = { db 91 [2] af 89 [2] e8 8b [2] af 9a [2] e1 96 [2] ed 9c [2] fa 97 [2] e1 d9 [2] dc }

  condition:
    any of them
}