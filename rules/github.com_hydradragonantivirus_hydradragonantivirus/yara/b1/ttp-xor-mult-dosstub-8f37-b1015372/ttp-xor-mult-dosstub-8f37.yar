rule TTP_XOR_MULT_DOSStub_8f37 {
  strings:
    $key_8f37 = { db 5f [2] af 47 [2] e8 45 [2] af 54 [2] e1 58 [2] ed 52 [2] fa 59 [2] e1 17 [2] dc }

  condition:
    any of them
}