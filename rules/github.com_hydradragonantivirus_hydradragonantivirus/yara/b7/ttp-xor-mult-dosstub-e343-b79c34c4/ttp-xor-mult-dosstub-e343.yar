rule TTP_XOR_MULT_DOSStub_e343 {
  strings:
    $key_e343 = { b7 2b [2] c3 33 [2] 84 31 [2] c3 20 [2] 8d 2c [2] 81 26 [2] 96 2d [2] 8d 63 [2] b0 }

  condition:
    any of them
}