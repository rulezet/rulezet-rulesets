rule TTP_XOR_MULT_DOSStub_8f2c {
  strings:
    $key_8f2c = { db 44 [2] af 5c [2] e8 5e [2] af 4f [2] e1 43 [2] ed 49 [2] fa 42 [2] e1 0c [2] dc }

  condition:
    any of them
}