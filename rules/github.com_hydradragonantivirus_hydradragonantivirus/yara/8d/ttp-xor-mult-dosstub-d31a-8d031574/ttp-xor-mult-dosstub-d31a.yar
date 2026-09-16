rule TTP_XOR_MULT_DOSStub_d31a {
  strings:
    $key_d31a = { 87 72 [2] f3 6a [2] b4 68 [2] f3 79 [2] bd 75 [2] b1 7f [2] a6 74 [2] bd 3a [2] 80 }

  condition:
    any of them
}