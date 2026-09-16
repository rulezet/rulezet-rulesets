rule TTP_XOR_MULT_DOSStub_e357 {
  strings:
    $key_e357 = { b7 3f [2] c3 27 [2] 84 25 [2] c3 34 [2] 8d 38 [2] 81 32 [2] 96 39 [2] 8d 77 [2] b0 }

  condition:
    any of them
}