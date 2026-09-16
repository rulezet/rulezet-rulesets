rule TTP_XOR_MULT_DOSStub_d323 {
  strings:
    $key_d323 = { 87 4b [2] f3 53 [2] b4 51 [2] f3 40 [2] bd 4c [2] b1 46 [2] a6 4d [2] bd 03 [2] 80 }

  condition:
    any of them
}