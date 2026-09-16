rule TTP_XOR_MULT_DOSStub_8f63 {
  strings:
    $key_8f63 = { db 0b [2] af 13 [2] e8 11 [2] af 00 [2] e1 0c [2] ed 06 [2] fa 0d [2] e1 43 [2] dc }

  condition:
    any of them
}