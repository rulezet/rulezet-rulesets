rule TTP_XOR_MULT_DOSStub_d852 {
  strings:
    $key_d852 = { 8c 3a [2] f8 22 [2] bf 20 [2] f8 31 [2] b6 3d [2] ba 37 [2] ad 3c [2] b6 72 [2] 8b }

  condition:
    any of them
}