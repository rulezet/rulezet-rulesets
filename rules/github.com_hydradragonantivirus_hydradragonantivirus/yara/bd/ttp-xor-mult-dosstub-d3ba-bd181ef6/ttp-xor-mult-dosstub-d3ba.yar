rule TTP_XOR_MULT_DOSStub_d3ba {
  strings:
    $key_d3ba = { 87 d2 [2] f3 ca [2] b4 c8 [2] f3 d9 [2] bd d5 [2] b1 df [2] a6 d4 [2] bd 9a [2] 80 }

  condition:
    any of them
}