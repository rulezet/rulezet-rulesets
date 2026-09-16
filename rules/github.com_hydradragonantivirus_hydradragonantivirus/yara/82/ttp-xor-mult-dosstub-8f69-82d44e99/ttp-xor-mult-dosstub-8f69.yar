rule TTP_XOR_MULT_DOSStub_8f69 {
  strings:
    $key_8f69 = { db 01 [2] af 19 [2] e8 1b [2] af 0a [2] e1 06 [2] ed 0c [2] fa 07 [2] e1 49 [2] dc }

  condition:
    any of them
}