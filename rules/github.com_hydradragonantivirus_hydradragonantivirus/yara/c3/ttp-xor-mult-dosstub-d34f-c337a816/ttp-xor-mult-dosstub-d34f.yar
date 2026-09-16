rule TTP_XOR_MULT_DOSStub_d34f {
  strings:
    $key_d34f = { 87 27 [2] f3 3f [2] b4 3d [2] f3 2c [2] bd 20 [2] b1 2a [2] a6 21 [2] bd 6f [2] 80 }

  condition:
    any of them
}