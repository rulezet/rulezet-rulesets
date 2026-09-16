rule TTP_XOR_MULT_DOSStub_8ffc {
  strings:
    $key_8ffc = { db 94 [2] af 8c [2] e8 8e [2] af 9f [2] e1 93 [2] ed 99 [2] fa 92 [2] e1 dc [2] dc }

  condition:
    any of them
}