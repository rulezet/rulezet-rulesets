rule TTP_XOR_MULT_DOSStub_e354 {
  strings:
    $key_e354 = { b7 3c [2] c3 24 [2] 84 26 [2] c3 37 [2] 8d 3b [2] 81 31 [2] 96 3a [2] 8d 74 [2] b0 }

  condition:
    any of them
}