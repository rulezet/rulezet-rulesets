rule TTP_XOR_MULT_DOSStub_d3e4 {
  strings:
    $key_d3e4 = { 87 8c [2] f3 94 [2] b4 96 [2] f3 87 [2] bd 8b [2] b1 81 [2] a6 8a [2] bd c4 [2] 80 }

  condition:
    any of them
}