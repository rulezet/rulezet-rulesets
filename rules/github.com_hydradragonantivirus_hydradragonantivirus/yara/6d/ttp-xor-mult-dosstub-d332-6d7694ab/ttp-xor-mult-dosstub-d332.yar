rule TTP_XOR_MULT_DOSStub_d332 {
  strings:
    $key_d332 = { 87 5a [2] f3 42 [2] b4 40 [2] f3 51 [2] bd 5d [2] b1 57 [2] a6 5c [2] bd 12 [2] 80 }

  condition:
    any of them
}