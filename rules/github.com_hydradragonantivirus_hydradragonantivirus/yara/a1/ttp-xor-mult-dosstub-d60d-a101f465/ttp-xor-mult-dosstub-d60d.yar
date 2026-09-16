rule TTP_XOR_MULT_DOSStub_d60d {
  strings:
    $key_d60d = { 82 65 [2] f6 7d [2] b1 7f [2] f6 6e [2] b8 62 [2] b4 68 [2] a3 63 [2] b8 2d [2] 85 }

  condition:
    any of them
}