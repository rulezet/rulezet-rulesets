rule TTP_XOR_MULT_DOSStub_c01d {
  strings:
    $key_c01d = { 94 75 [2] e0 6d [2] a7 6f [2] e0 7e [2] ae 72 [2] a2 78 [2] b5 73 [2] ae 3d [2] 93 }

  condition:
    any of them
}