rule TTP_XOR_MULT_DOSStub_e340 {
  strings:
    $key_e340 = { b7 28 [2] c3 30 [2] 84 32 [2] c3 23 [2] 8d 2f [2] 81 25 [2] 96 2e [2] 8d 60 [2] b0 }

  condition:
    any of them
}