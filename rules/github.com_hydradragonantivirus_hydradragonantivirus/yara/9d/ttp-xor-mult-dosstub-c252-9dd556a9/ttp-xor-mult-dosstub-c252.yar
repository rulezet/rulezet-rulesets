rule TTP_XOR_MULT_DOSStub_c252 {
  strings:
    $key_c252 = { 96 3a [2] e2 22 [2] a5 20 [2] e2 31 [2] ac 3d [2] a0 37 [2] b7 3c [2] ac 72 [2] 91 }

  condition:
    any of them
}