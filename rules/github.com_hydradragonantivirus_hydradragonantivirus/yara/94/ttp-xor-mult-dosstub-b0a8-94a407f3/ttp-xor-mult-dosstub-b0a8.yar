rule TTP_XOR_MULT_DOSStub_b0a8 {
  strings:
    $key_b0a8 = { e4 c0 [2] 90 d8 [2] d7 da [2] 90 cb [2] de c7 [2] d2 cd [2] c5 c6 [2] de 88 [2] e3 }

  condition:
    any of them
}