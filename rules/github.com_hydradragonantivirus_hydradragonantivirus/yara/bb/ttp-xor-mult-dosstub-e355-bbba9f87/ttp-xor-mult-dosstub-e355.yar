rule TTP_XOR_MULT_DOSStub_e355 {
  strings:
    $key_e355 = { b7 3d [2] c3 25 [2] 84 27 [2] c3 36 [2] 8d 3a [2] 81 30 [2] 96 3b [2] 8d 75 [2] b0 }

  condition:
    any of them
}