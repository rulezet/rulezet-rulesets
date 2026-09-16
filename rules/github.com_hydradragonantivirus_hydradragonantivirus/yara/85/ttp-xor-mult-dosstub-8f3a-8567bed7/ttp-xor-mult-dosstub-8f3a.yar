rule TTP_XOR_MULT_DOSStub_8f3a {
  strings:
    $key_8f3a = { db 52 [2] af 4a [2] e8 48 [2] af 59 [2] e1 55 [2] ed 5f [2] fa 54 [2] e1 1a [2] dc }

  condition:
    any of them
}