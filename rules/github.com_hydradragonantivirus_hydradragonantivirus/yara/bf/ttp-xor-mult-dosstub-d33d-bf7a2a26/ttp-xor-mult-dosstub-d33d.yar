rule TTP_XOR_MULT_DOSStub_d33d {
  strings:
    $key_d33d = { 87 55 [2] f3 4d [2] b4 4f [2] f3 5e [2] bd 52 [2] b1 58 [2] a6 53 [2] bd 1d [2] 80 }

  condition:
    any of them
}