rule TTP_XOR_MULT_DOSStub_d37c {
  strings:
    $key_d37c = { 87 14 [2] f3 0c [2] b4 0e [2] f3 1f [2] bd 13 [2] b1 19 [2] a6 12 [2] bd 5c [2] 80 }

  condition:
    any of them
}