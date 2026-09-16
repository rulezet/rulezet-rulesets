rule TTP_XOR_MULT_DOSStub_8f2e {
  strings:
    $key_8f2e = { db 46 [2] af 5e [2] e8 5c [2] af 4d [2] e1 41 [2] ed 4b [2] fa 40 [2] e1 0e [2] dc }

  condition:
    any of them
}