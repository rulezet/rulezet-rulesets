rule TTP_XOR_MULT_DOSStub_d3f2 {
  strings:
    $key_d3f2 = { 87 9a [2] f3 82 [2] b4 80 [2] f3 91 [2] bd 9d [2] b1 97 [2] a6 9c [2] bd d2 [2] 80 }

  condition:
    any of them
}