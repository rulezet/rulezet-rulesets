rule TTP_XOR_MULT_DOSStub_e375 {
  strings:
    $key_e375 = { b7 1d [2] c3 05 [2] 84 07 [2] c3 16 [2] 8d 1a [2] 81 10 [2] 96 1b [2] 8d 55 [2] b0 }

  condition:
    any of them
}