rule TTP_XOR_MULT_DOSStub_a74f {
  strings:
    $key_a74f = { f3 27 [2] 87 3f [2] c0 3d [2] 87 2c [2] c9 20 [2] c5 2a [2] d2 21 [2] c9 6f [2] f4 }

  condition:
    any of them
}