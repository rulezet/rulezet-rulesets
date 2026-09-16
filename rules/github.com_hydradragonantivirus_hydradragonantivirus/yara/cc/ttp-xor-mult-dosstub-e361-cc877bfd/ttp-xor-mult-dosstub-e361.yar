rule TTP_XOR_MULT_DOSStub_e361 {
  strings:
    $key_e361 = { b7 09 [2] c3 11 [2] 84 13 [2] c3 02 [2] 8d 0e [2] 81 04 [2] 96 0f [2] 8d 41 [2] b0 }

  condition:
    any of them
}