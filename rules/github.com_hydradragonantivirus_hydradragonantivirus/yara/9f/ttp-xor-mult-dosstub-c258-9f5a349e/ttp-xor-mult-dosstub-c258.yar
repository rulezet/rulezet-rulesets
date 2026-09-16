rule TTP_XOR_MULT_DOSStub_c258 {
  strings:
    $key_c258 = { 96 30 [2] e2 28 [2] a5 2a [2] e2 3b [2] ac 37 [2] a0 3d [2] b7 36 [2] ac 78 [2] 91 }

  condition:
    any of them
}