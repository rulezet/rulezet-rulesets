rule TTP_XOR_MULT_DOSStub_c44d {
  strings:
    $key_c44d = { 90 25 [2] e4 3d [2] a3 3f [2] e4 2e [2] aa 22 [2] a6 28 [2] b1 23 [2] aa 6d [2] 97 }

  condition:
    any of them
}