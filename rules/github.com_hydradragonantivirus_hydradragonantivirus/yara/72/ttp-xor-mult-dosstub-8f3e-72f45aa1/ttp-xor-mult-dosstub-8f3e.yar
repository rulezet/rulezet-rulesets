rule TTP_XOR_MULT_DOSStub_8f3e {
  strings:
    $key_8f3e = { db 56 [2] af 4e [2] e8 4c [2] af 5d [2] e1 51 [2] ed 5b [2] fa 50 [2] e1 1e [2] dc }

  condition:
    any of them
}