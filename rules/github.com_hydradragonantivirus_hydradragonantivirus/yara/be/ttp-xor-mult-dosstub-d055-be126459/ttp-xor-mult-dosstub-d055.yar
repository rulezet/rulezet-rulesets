rule TTP_XOR_MULT_DOSStub_d055 {
  strings:
    $key_d055 = { 84 3d [2] f0 25 [2] b7 27 [2] f0 36 [2] be 3a [2] b2 30 [2] a5 3b [2] be 75 [2] 83 }

  condition:
    any of them
}