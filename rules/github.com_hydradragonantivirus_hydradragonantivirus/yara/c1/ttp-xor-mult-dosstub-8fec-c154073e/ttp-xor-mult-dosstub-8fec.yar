rule TTP_XOR_MULT_DOSStub_8fec {
  strings:
    $key_8fec = { db 84 [2] af 9c [2] e8 9e [2] af 8f [2] e1 83 [2] ed 89 [2] fa 82 [2] e1 cc [2] dc }

  condition:
    any of them
}