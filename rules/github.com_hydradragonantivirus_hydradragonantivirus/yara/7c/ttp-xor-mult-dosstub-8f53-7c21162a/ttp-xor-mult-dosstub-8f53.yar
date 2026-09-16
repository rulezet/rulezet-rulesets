rule TTP_XOR_MULT_DOSStub_8f53 {
  strings:
    $key_8f53 = { db 3b [2] af 23 [2] e8 21 [2] af 30 [2] e1 3c [2] ed 36 [2] fa 3d [2] e1 73 [2] dc }

  condition:
    any of them
}