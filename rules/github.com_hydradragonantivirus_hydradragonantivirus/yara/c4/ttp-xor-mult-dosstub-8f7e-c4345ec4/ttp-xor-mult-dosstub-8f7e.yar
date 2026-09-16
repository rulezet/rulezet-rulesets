rule TTP_XOR_MULT_DOSStub_8f7e {
  strings:
    $key_8f7e = { db 16 [2] af 0e [2] e8 0c [2] af 1d [2] e1 11 [2] ed 1b [2] fa 10 [2] e1 5e [2] dc }

  condition:
    any of them
}