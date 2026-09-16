rule TTP_XOR_MULT_DOSStub_e373 {
  strings:
    $key_e373 = { b7 1b [2] c3 03 [2] 84 01 [2] c3 10 [2] 8d 1c [2] 81 16 [2] 96 1d [2] 8d 53 [2] b0 }

  condition:
    any of them
}