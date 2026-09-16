rule TTP_XOR_MULT_DOSStub_8f06 {
  strings:
    $key_8f06 = { db 6e [2] af 76 [2] e8 74 [2] af 65 [2] e1 69 [2] ed 63 [2] fa 68 [2] e1 26 [2] dc }

  condition:
    any of them
}