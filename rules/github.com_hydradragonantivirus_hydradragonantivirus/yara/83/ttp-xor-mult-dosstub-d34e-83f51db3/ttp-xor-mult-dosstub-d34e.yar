rule TTP_XOR_MULT_DOSStub_d34e {
  strings:
    $key_d34e = { 87 26 [2] f3 3e [2] b4 3c [2] f3 2d [2] bd 21 [2] b1 2b [2] a6 20 [2] bd 6e [2] 80 }

  condition:
    any of them
}