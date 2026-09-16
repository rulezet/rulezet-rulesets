rule TTP_XOR_MULT_DOSStub_d74b {
  strings:
    $key_d74b = { 83 23 [2] f7 3b [2] b0 39 [2] f7 28 [2] b9 24 [2] b5 2e [2] a2 25 [2] b9 6b [2] 84 }

  condition:
    any of them
}