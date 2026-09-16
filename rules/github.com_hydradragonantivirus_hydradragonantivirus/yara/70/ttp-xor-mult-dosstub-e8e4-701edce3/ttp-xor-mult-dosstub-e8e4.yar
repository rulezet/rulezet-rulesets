rule TTP_XOR_MULT_DOSStub_e8e4 {
  strings:
    $key_e8e4 = { bc 8c [2] c8 94 [2] 8f 96 [2] c8 87 [2] 86 8b [2] 8a 81 [2] 9d 8a [2] 86 c4 [2] bb }

  condition:
    any of them
}