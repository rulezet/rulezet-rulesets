rule TTP_XOR_MULT_DOSStub_8f7b {
  strings:
    $key_8f7b = { db 13 [2] af 0b [2] e8 09 [2] af 18 [2] e1 14 [2] ed 1e [2] fa 15 [2] e1 5b [2] dc }

  condition:
    any of them
}