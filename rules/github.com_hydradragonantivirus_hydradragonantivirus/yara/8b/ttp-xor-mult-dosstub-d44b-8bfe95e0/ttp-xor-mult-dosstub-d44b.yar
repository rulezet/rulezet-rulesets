rule TTP_XOR_MULT_DOSStub_d44b {
  strings:
    $key_d44b = { 80 23 [2] f4 3b [2] b3 39 [2] f4 28 [2] ba 24 [2] b6 2e [2] a1 25 [2] ba 6b [2] 87 }

  condition:
    any of them
}