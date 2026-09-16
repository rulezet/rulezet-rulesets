rule TTP_XOR_MULT_DOSStub_d324 {
  strings:
    $key_d324 = { 87 4c [2] f3 54 [2] b4 56 [2] f3 47 [2] bd 4b [2] b1 41 [2] a6 4a [2] bd 04 [2] 80 }

  condition:
    any of them
}