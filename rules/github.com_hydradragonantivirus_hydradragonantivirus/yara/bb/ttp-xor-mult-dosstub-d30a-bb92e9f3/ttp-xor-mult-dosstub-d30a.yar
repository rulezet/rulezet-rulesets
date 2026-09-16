rule TTP_XOR_MULT_DOSStub_d30a {
  strings:
    $key_d30a = { 87 62 [2] f3 7a [2] b4 78 [2] f3 69 [2] bd 65 [2] b1 6f [2] a6 64 [2] bd 2a [2] 80 }

  condition:
    any of them
}