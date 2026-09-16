rule TTP_XOR_MULT_DOSStub_e348 {
  strings:
    $key_e348 = { b7 20 [2] c3 38 [2] 84 3a [2] c3 2b [2] 8d 27 [2] 81 2d [2] 96 26 [2] 8d 68 [2] b0 }

  condition:
    any of them
}