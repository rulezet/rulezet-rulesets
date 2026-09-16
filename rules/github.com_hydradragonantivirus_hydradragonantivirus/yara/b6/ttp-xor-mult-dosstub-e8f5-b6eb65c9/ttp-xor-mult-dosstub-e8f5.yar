rule TTP_XOR_MULT_DOSStub_e8f5 {
  strings:
    $key_e8f5 = { bc 9d [2] c8 85 [2] 8f 87 [2] c8 96 [2] 86 9a [2] 8a 90 [2] 9d 9b [2] 86 d5 [2] bb }

  condition:
    any of them
}