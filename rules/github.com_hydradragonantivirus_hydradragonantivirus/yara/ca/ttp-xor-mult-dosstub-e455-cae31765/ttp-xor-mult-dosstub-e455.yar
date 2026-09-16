rule TTP_XOR_MULT_DOSStub_e455 {
  strings:
    $key_e455 = { b0 3d [2] c4 25 [2] 83 27 [2] c4 36 [2] 8a 3a [2] 86 30 [2] 91 3b [2] 8a 75 [2] b7 }

  condition:
    any of them
}