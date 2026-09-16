rule TTP_XOR_MULT_DOSStub_8f3d {
  strings:
    $key_8f3d = { db 55 [2] af 4d [2] e8 4f [2] af 5e [2] e1 52 [2] ed 58 [2] fa 53 [2] e1 1d [2] dc }

  condition:
    any of them
}