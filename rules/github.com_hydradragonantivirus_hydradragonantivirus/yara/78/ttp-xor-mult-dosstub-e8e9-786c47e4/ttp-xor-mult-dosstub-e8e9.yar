rule TTP_XOR_MULT_DOSStub_e8e9 {
  strings:
    $key_e8e9 = { bc 81 [2] c8 99 [2] 8f 9b [2] c8 8a [2] 86 86 [2] 8a 8c [2] 9d 87 [2] 86 c9 [2] bb }

  condition:
    any of them
}