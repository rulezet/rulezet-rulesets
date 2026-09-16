rule TTP_XOR_MULT_DOSStub_8f62 {
  strings:
    $key_8f62 = { db 0a [2] af 12 [2] e8 10 [2] af 01 [2] e1 0d [2] ed 07 [2] fa 0c [2] e1 42 [2] dc }

  condition:
    any of them
}