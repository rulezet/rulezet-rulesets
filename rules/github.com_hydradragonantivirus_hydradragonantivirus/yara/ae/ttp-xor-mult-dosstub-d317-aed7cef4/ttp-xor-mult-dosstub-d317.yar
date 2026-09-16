rule TTP_XOR_MULT_DOSStub_d317 {
  strings:
    $key_d317 = { 87 7f [2] f3 67 [2] b4 65 [2] f3 74 [2] bd 78 [2] b1 72 [2] a6 79 [2] bd 37 [2] 80 }

  condition:
    any of them
}