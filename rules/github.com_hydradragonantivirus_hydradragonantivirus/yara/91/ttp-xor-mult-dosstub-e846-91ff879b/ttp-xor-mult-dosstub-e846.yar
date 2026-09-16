rule TTP_XOR_MULT_DOSStub_e846 {
  strings:
    $key_e846 = { bc 2e [2] c8 36 [2] 8f 34 [2] c8 25 [2] 86 29 [2] 8a 23 [2] 9d 28 [2] 86 66 [2] bb }

  condition:
    any of them
}