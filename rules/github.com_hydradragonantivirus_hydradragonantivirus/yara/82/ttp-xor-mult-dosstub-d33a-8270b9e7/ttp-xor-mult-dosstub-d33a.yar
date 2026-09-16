rule TTP_XOR_MULT_DOSStub_d33a {
  strings:
    $key_d33a = { 87 52 [2] f3 4a [2] b4 48 [2] f3 59 [2] bd 55 [2] b1 5f [2] a6 54 [2] bd 1a [2] 80 }

  condition:
    any of them
}