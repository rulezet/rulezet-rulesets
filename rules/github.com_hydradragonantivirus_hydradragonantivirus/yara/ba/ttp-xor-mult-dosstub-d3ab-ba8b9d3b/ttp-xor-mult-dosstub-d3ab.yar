rule TTP_XOR_MULT_DOSStub_d3ab {
  strings:
    $key_d3ab = { 87 c3 [2] f3 db [2] b4 d9 [2] f3 c8 [2] bd c4 [2] b1 ce [2] a6 c5 [2] bd 8b [2] 80 }

  condition:
    any of them
}