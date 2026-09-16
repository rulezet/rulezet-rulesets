rule TTP_XOR_MULT_DOSStub_d3f6 {
  strings:
    $key_d3f6 = { 87 9e [2] f3 86 [2] b4 84 [2] f3 95 [2] bd 99 [2] b1 93 [2] a6 98 [2] bd d6 [2] 80 }

  condition:
    any of them
}