rule TTP_XOR_MULT_DOSStub_d3b8 {
  strings:
    $key_d3b8 = { 87 d0 [2] f3 c8 [2] b4 ca [2] f3 db [2] bd d7 [2] b1 dd [2] a6 d6 [2] bd 98 [2] 80 }

  condition:
    any of them
}