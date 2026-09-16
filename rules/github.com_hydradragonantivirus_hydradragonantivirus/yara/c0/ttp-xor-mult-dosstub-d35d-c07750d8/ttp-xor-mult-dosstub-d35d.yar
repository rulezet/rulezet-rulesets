rule TTP_XOR_MULT_DOSStub_d35d {
  strings:
    $key_d35d = { 87 35 [2] f3 2d [2] b4 2f [2] f3 3e [2] bd 32 [2] b1 38 [2] a6 33 [2] bd 7d [2] 80 }

  condition:
    any of them
}