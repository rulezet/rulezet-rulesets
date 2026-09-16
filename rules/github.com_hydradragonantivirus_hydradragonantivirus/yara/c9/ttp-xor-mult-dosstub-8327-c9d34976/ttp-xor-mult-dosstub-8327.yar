rule TTP_XOR_MULT_DOSStub_8327 {
  strings:
    $key_8327 = { d7 4f [2] a3 57 [2] e4 55 [2] a3 44 [2] ed 48 [2] e1 42 [2] f6 49 [2] ed 07 [2] d0 }

  condition:
    any of them
}