rule TTP_XOR_MULT_DOSStub_8f1c {
  strings:
    $key_8f1c = { db 74 [2] af 6c [2] e8 6e [2] af 7f [2] e1 73 [2] ed 79 [2] fa 72 [2] e1 3c [2] dc }

  condition:
    any of them
}