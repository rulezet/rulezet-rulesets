rule TTP_XOR_MULT_DOSStub_d67b {
  strings:
    $key_d67b = { 82 13 [2] f6 0b [2] b1 09 [2] f6 18 [2] b8 14 [2] b4 1e [2] a3 15 [2] b8 5b [2] 85 }

  condition:
    any of them
}