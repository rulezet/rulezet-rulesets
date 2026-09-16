rule TTP_XOR_MULT_DOSStub_d3e0 {
  strings:
    $key_d3e0 = { 87 88 [2] f3 90 [2] b4 92 [2] f3 83 [2] bd 8f [2] b1 85 [2] a6 8e [2] bd c0 [2] 80 }

  condition:
    any of them
}