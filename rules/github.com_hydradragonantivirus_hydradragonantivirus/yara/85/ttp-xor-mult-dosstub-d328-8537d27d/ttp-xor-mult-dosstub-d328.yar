rule TTP_XOR_MULT_DOSStub_d328 {
  strings:
    $key_d328 = { 87 40 [2] f3 58 [2] b4 5a [2] f3 4b [2] bd 47 [2] b1 4d [2] a6 46 [2] bd 08 [2] 80 }

  condition:
    any of them
}