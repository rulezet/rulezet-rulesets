rule TTP_XOR_MULT_DOSStub_e130 {
  strings:
    $key_e130 = { b5 58 [2] c1 40 [2] 86 42 [2] c1 53 [2] 8f 5f [2] 83 55 [2] 94 5e [2] 8f 10 [2] b2 }

  condition:
    any of them
}