rule TTP_XOR_MULT_DOSStub_8f2a {
  strings:
    $key_8f2a = { db 42 [2] af 5a [2] e8 58 [2] af 49 [2] e1 45 [2] ed 4f [2] fa 44 [2] e1 0a [2] dc }

  condition:
    any of them
}