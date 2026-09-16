rule TTP_XOR_MULT_DOSStub_d304 {
  strings:
    $key_d304 = { 87 6c [2] f3 74 [2] b4 76 [2] f3 67 [2] bd 6b [2] b1 61 [2] a6 6a [2] bd 24 [2] 80 }

  condition:
    any of them
}