rule TTP_XOR_MULT_DOSStub_d3b3 {
  strings:
    $key_d3b3 = { 87 db [2] f3 c3 [2] b4 c1 [2] f3 d0 [2] bd dc [2] b1 d6 [2] a6 dd [2] bd 93 [2] 80 }

  condition:
    any of them
}