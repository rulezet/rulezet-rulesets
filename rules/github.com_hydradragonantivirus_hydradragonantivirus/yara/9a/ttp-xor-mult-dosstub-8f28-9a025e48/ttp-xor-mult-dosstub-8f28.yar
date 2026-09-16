rule TTP_XOR_MULT_DOSStub_8f28 {
  strings:
    $key_8f28 = { db 40 [2] af 58 [2] e8 5a [2] af 4b [2] e1 47 [2] ed 4d [2] fa 46 [2] e1 08 [2] dc }

  condition:
    any of them
}