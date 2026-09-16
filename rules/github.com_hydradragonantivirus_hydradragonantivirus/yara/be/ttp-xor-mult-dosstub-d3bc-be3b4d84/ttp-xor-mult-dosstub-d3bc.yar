rule TTP_XOR_MULT_DOSStub_d3bc {
  strings:
    $key_d3bc = { 87 d4 [2] f3 cc [2] b4 ce [2] f3 df [2] bd d3 [2] b1 d9 [2] a6 d2 [2] bd 9c [2] 80 }

  condition:
    any of them
}