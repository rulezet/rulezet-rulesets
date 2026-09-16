rule TTP_XOR_MULT_DOSStub_d3eb {
  strings:
    $key_d3eb = { 87 83 [2] f3 9b [2] b4 99 [2] f3 88 [2] bd 84 [2] b1 8e [2] a6 85 [2] bd cb [2] 80 }

  condition:
    any of them
}