rule TTP_XOR_MULT_DOSStub_d67d {
  strings:
    $key_d67d = { 82 15 [2] f6 0d [2] b1 0f [2] f6 1e [2] b8 12 [2] b4 18 [2] a3 13 [2] b8 5d [2] 85 }

  condition:
    any of them
}