rule TTP_XOR_MULT_DOSStub_8f1f {
  strings:
    $key_8f1f = { db 77 [2] af 6f [2] e8 6d [2] af 7c [2] e1 70 [2] ed 7a [2] fa 71 [2] e1 3f [2] dc }

  condition:
    any of them
}