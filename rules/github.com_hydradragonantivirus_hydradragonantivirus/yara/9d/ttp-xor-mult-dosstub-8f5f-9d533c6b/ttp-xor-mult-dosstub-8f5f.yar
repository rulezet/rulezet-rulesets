rule TTP_XOR_MULT_DOSStub_8f5f {
  strings:
    $key_8f5f = { db 37 [2] af 2f [2] e8 2d [2] af 3c [2] e1 30 [2] ed 3a [2] fa 31 [2] e1 7f [2] dc }

  condition:
    any of them
}