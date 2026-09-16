rule TTP_XOR_MULT_DOSStub_e155 {
  strings:
    $key_e155 = { b5 3d [2] c1 25 [2] 86 27 [2] c1 36 [2] 8f 3a [2] 83 30 [2] 94 3b [2] 8f 75 [2] b2 }

  condition:
    any of them
}