rule TTP_XOR_MULT_DOSStub_c61d {
  strings:
    $key_c61d = { 92 75 [2] e6 6d [2] a1 6f [2] e6 7e [2] a8 72 [2] a4 78 [2] b3 73 [2] a8 3d [2] 95 }

  condition:
    any of them
}