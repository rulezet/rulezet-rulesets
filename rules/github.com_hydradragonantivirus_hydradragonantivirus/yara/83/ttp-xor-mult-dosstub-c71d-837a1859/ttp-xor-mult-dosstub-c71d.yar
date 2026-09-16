rule TTP_XOR_MULT_DOSStub_c71d {
  strings:
    $key_c71d = { 93 75 [2] e7 6d [2] a0 6f [2] e7 7e [2] a9 72 [2] a5 78 [2] b2 73 [2] a9 3d [2] 94 }

  condition:
    any of them
}