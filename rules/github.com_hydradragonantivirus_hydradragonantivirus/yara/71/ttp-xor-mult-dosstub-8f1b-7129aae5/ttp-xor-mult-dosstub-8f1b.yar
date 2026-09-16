rule TTP_XOR_MULT_DOSStub_8f1b {
  strings:
    $key_8f1b = { db 73 [2] af 6b [2] e8 69 [2] af 78 [2] e1 74 [2] ed 7e [2] fa 75 [2] e1 3b [2] dc }

  condition:
    any of them
}