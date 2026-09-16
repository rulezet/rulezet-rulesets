rule TTP_XOR_MULT_DOSStub_d34b {
  strings:
    $key_d34b = { 87 23 [2] f3 3b [2] b4 39 [2] f3 28 [2] bd 24 [2] b1 2e [2] a6 25 [2] bd 6b [2] 80 }

  condition:
    any of them
}