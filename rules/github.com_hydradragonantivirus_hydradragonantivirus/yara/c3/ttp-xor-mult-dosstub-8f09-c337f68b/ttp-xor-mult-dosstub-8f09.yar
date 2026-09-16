rule TTP_XOR_MULT_DOSStub_8f09 {
  strings:
    $key_8f09 = { db 61 [2] af 79 [2] e8 7b [2] af 6a [2] e1 66 [2] ed 6c [2] fa 67 [2] e1 29 [2] dc }

  condition:
    any of them
}