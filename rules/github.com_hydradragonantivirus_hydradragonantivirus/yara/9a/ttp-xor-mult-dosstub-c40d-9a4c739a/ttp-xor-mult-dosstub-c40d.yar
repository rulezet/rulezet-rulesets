rule TTP_XOR_MULT_DOSStub_c40d {
  strings:
    $key_c40d = { 90 65 [2] e4 7d [2] a3 7f [2] e4 6e [2] aa 62 [2] a6 68 [2] b1 63 [2] aa 2d [2] 97 }

  condition:
    any of them
}