rule TTP_XOR_MULT_DOSStub_d67c {
  strings:
    $key_d67c = { 82 14 [2] f6 0c [2] b1 0e [2] f6 1f [2] b8 13 [2] b4 19 [2] a3 12 [2] b8 5c [2] 85 }

  condition:
    any of them
}