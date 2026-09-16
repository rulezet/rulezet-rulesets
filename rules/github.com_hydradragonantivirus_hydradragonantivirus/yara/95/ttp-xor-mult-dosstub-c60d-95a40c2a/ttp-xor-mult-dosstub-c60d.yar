rule TTP_XOR_MULT_DOSStub_c60d {
  strings:
    $key_c60d = { 92 65 [2] e6 7d [2] a1 7f [2] e6 6e [2] a8 62 [2] a4 68 [2] b3 63 [2] a8 2d [2] 95 }

  condition:
    any of them
}