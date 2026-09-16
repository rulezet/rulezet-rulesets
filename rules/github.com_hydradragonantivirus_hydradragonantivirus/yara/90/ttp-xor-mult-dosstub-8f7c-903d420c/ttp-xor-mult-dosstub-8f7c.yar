rule TTP_XOR_MULT_DOSStub_8f7c {
  strings:
    $key_8f7c = { db 14 [2] af 0c [2] e8 0e [2] af 1f [2] e1 13 [2] ed 19 [2] fa 12 [2] e1 5c [2] dc }

  condition:
    any of them
}