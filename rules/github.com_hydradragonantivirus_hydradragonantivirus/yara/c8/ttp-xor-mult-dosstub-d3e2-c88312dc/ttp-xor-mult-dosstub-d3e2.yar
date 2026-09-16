rule TTP_XOR_MULT_DOSStub_d3e2 {
  strings:
    $key_d3e2 = { 87 8a [2] f3 92 [2] b4 90 [2] f3 81 [2] bd 8d [2] b1 87 [2] a6 8c [2] bd c2 [2] 80 }

  condition:
    any of them
}