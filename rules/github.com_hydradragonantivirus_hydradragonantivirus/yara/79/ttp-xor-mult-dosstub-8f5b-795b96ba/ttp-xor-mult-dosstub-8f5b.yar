rule TTP_XOR_MULT_DOSStub_8f5b {
  strings:
    $key_8f5b = { db 33 [2] af 2b [2] e8 29 [2] af 38 [2] e1 34 [2] ed 3e [2] fa 35 [2] e1 7b [2] dc }

  condition:
    any of them
}