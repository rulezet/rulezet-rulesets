rule TTP_XOR_MULT_DOSStub_d401 {
  strings:
    $key_d401 = { 80 69 [2] f4 71 [2] b3 73 [2] f4 62 [2] ba 6e [2] b6 64 [2] a1 6f [2] ba 21 [2] 87 }

  condition:
    any of them
}