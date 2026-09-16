rule TTP_XOR_MULT_DOSStub_e341 {
  strings:
    $key_e341 = { b7 29 [2] c3 31 [2] 84 33 [2] c3 22 [2] 8d 2e [2] 81 24 [2] 96 2f [2] 8d 61 [2] b0 }

  condition:
    any of them
}