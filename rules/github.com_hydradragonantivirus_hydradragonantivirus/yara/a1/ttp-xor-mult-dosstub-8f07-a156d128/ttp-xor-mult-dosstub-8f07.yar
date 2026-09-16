rule TTP_XOR_MULT_DOSStub_8f07 {
  strings:
    $key_8f07 = { db 6f [2] af 77 [2] e8 75 [2] af 64 [2] e1 68 [2] ed 62 [2] fa 69 [2] e1 27 [2] dc }

  condition:
    any of them
}