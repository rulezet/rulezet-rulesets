rule TTP_XOR_MULT_DOSStub_d352 {
  strings:
    $key_d352 = { 87 3a [2] f3 22 [2] b4 20 [2] f3 31 [2] bd 3d [2] b1 37 [2] a6 3c [2] bd 72 [2] 80 }

  condition:
    any of them
}