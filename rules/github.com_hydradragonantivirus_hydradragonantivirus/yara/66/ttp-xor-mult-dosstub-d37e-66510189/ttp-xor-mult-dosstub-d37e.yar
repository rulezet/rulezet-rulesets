rule TTP_XOR_MULT_DOSStub_d37e {
  strings:
    $key_d37e = { 87 16 [2] f3 0e [2] b4 0c [2] f3 1d [2] bd 11 [2] b1 1b [2] a6 10 [2] bd 5e [2] 80 }

  condition:
    any of them
}