rule TTP_XOR_MULT_DOSStub_d310 {
  strings:
    $key_d310 = { 87 78 [2] f3 60 [2] b4 62 [2] f3 73 [2] bd 7f [2] b1 75 [2] a6 7e [2] bd 30 [2] 80 }

  condition:
    any of them
}