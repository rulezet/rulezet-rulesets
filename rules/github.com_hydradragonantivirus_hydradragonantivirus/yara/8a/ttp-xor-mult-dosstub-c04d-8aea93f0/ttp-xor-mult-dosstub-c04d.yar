rule TTP_XOR_MULT_DOSStub_c04d {
  strings:
    $key_c04d = { 94 25 [2] e0 3d [2] a7 3f [2] e0 2e [2] ae 22 [2] a2 28 [2] b5 23 [2] ae 6d [2] 93 }

  condition:
    any of them
}