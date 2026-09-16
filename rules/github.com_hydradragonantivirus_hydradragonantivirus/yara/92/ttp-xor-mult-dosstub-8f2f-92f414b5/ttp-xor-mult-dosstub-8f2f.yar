rule TTP_XOR_MULT_DOSStub_8f2f {
  strings:
    $key_8f2f = { db 47 [2] af 5f [2] e8 5d [2] af 4c [2] e1 40 [2] ed 4a [2] fa 41 [2] e1 0f [2] dc }

  condition:
    any of them
}