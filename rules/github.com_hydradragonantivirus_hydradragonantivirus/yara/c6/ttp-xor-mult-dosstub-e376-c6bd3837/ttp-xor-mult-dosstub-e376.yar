rule TTP_XOR_MULT_DOSStub_e376 {
  strings:
    $key_e376 = { b7 1e [2] c3 06 [2] 84 04 [2] c3 15 [2] 8d 19 [2] 81 13 [2] 96 18 [2] 8d 56 [2] b0 }

  condition:
    any of them
}