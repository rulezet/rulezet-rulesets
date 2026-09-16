rule TTP_XOR_MULT_DOSStub_d335 {
  strings:
    $key_d335 = { 87 5d [2] f3 45 [2] b4 47 [2] f3 56 [2] bd 5a [2] b1 50 [2] a6 5b [2] bd 15 [2] 80 }

  condition:
    any of them
}