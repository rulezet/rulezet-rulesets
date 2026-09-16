rule TTP_XOR_MULT_DOSStub_d654 {
  strings:
    $key_d654 = { 82 3c [2] f6 24 [2] b1 26 [2] f6 37 [2] b8 3b [2] b4 31 [2] a3 3a [2] b8 74 [2] 85 }

  condition:
    any of them
}