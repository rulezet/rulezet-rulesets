rule TTP_XOR_MULT_DOSStub_d37d {
  strings:
    $key_d37d = { 87 15 [2] f3 0d [2] b4 0f [2] f3 1e [2] bd 12 [2] b1 18 [2] a6 13 [2] bd 5d [2] 80 }

  condition:
    any of them
}