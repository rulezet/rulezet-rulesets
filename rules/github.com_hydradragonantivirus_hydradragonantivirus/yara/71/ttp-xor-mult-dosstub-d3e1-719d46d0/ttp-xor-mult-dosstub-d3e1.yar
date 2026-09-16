rule TTP_XOR_MULT_DOSStub_d3e1 {
  strings:
    $key_d3e1 = { 87 89 [2] f3 91 [2] b4 93 [2] f3 82 [2] bd 8e [2] b1 84 [2] a6 8f [2] bd c1 [2] 80 }

  condition:
    any of them
}