rule TTP_XOR_MULT_DOSStub_8ff4 {
  strings:
    $key_8ff4 = { db 9c [2] af 84 [2] e8 86 [2] af 97 [2] e1 9b [2] ed 91 [2] fa 9a [2] e1 d4 [2] dc }

  condition:
    any of them
}