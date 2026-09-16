rule TTP_XOR_MULT_DOSStub_e8e6 {
  strings:
    $key_e8e6 = { bc 8e [2] c8 96 [2] 8f 94 [2] c8 85 [2] 86 89 [2] 8a 83 [2] 9d 88 [2] 86 c6 [2] bb }

  condition:
    any of them
}