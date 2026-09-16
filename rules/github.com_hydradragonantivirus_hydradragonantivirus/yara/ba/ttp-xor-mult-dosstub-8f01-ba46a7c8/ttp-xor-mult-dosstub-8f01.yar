rule TTP_XOR_MULT_DOSStub_8f01 {
  strings:
    $key_8f01 = { db 69 [2] af 71 [2] e8 73 [2] af 62 [2] e1 6e [2] ed 64 [2] fa 6f [2] e1 21 [2] dc }

  condition:
    any of them
}