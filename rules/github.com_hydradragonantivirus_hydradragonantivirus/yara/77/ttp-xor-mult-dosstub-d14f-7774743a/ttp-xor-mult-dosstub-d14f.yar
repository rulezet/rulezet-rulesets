rule TTP_XOR_MULT_DOSStub_d14f {
  strings:
    $key_d14f = { 85 27 [2] f1 3f [2] b6 3d [2] f1 2c [2] bf 20 [2] b3 2a [2] a4 21 [2] bf 6f [2] 82 }

  condition:
    any of them
}