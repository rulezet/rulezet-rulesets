rule TTP_XOR_MULT_DOSStub_c43d {
  strings:
    $key_c43d = { 90 55 [2] e4 4d [2] a3 4f [2] e4 5e [2] aa 52 [2] a6 58 [2] b1 53 [2] aa 1d [2] 97 }

  condition:
    any of them
}