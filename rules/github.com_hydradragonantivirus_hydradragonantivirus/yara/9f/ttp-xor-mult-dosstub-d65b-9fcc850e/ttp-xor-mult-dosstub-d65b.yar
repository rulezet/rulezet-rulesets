rule TTP_XOR_MULT_DOSStub_d65b {
  strings:
    $key_d65b = { 82 33 [2] f6 2b [2] b1 29 [2] f6 38 [2] b8 34 [2] b4 3e [2] a3 35 [2] b8 7b [2] 85 }

  condition:
    any of them
}