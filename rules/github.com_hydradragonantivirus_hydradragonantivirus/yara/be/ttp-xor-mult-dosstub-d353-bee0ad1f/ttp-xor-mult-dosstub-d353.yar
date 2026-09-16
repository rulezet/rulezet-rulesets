rule TTP_XOR_MULT_DOSStub_d353 {
  strings:
    $key_d353 = { 87 3b [2] f3 23 [2] b4 21 [2] f3 30 [2] bd 3c [2] b1 36 [2] a6 3d [2] bd 73 [2] 80 }

  condition:
    any of them
}