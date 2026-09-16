rule TTP_XOR_MULT_DOSStub_d37f {
  strings:
    $key_d37f = { 87 17 [2] f3 0f [2] b4 0d [2] f3 1c [2] bd 10 [2] b1 1a [2] a6 11 [2] bd 5f [2] 80 }

  condition:
    any of them
}