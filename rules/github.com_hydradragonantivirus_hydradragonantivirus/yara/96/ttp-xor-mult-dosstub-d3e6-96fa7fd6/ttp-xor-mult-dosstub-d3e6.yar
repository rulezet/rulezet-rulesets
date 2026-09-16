rule TTP_XOR_MULT_DOSStub_d3e6 {
  strings:
    $key_d3e6 = { 87 8e [2] f3 96 [2] b4 94 [2] f3 85 [2] bd 89 [2] b1 83 [2] a6 88 [2] bd c6 [2] 80 }

  condition:
    any of them
}