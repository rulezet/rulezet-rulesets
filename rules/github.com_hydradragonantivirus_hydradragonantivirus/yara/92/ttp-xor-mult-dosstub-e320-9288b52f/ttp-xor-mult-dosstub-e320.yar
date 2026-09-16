rule TTP_XOR_MULT_DOSStub_e320 {
  strings:
    $key_e320 = { b7 48 [2] c3 50 [2] 84 52 [2] c3 43 [2] 8d 4f [2] 81 45 [2] 96 4e [2] 8d 00 [2] b0 }

  condition:
    any of them
}