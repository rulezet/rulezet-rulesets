rule TTP_XOR_MULT_DOSStub_e330 {
  strings:
    $key_e330 = { b7 58 [2] c3 40 [2] 84 42 [2] c3 53 [2] 8d 5f [2] 81 55 [2] 96 5e [2] 8d 10 [2] b0 }

  condition:
    any of them
}