rule TTP_XOR_MULT_DOSStub_d74f {
  strings:
    $key_d74f = { 83 27 [2] f7 3f [2] b0 3d [2] f7 2c [2] b9 20 [2] b5 2a [2] a2 21 [2] b9 6f [2] 84 }

  condition:
    any of them
}