rule TTP_XOR_MULT_DOSStub_8fee {
  strings:
    $key_8fee = { db 86 [2] af 9e [2] e8 9c [2] af 8d [2] e1 81 [2] ed 8b [2] fa 80 [2] e1 ce [2] dc }

  condition:
    any of them
}