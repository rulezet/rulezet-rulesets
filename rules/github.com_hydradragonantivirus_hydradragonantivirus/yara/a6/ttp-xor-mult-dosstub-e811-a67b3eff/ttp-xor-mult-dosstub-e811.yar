rule TTP_XOR_MULT_DOSStub_e811 {
  strings:
    $key_e811 = { bc 79 [2] c8 61 [2] 8f 63 [2] c8 72 [2] 86 7e [2] 8a 74 [2] 9d 7f [2] 86 31 [2] bb }

  condition:
    any of them
}