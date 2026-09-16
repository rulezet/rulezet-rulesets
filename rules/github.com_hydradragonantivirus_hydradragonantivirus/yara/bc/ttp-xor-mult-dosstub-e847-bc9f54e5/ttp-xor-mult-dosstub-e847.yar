rule TTP_XOR_MULT_DOSStub_e847 {
  strings:
    $key_e847 = { bc 2f [2] c8 37 [2] 8f 35 [2] c8 24 [2] 86 28 [2] 8a 22 [2] 9d 29 [2] 86 67 [2] bb }

  condition:
    any of them
}