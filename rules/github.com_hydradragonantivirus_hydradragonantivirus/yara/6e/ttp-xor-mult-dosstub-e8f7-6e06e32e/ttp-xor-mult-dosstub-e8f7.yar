rule TTP_XOR_MULT_DOSStub_e8f7 {
  strings:
    $key_e8f7 = { bc 9f [2] c8 87 [2] 8f 85 [2] c8 94 [2] 86 98 [2] 8a 92 [2] 9d 99 [2] 86 d7 [2] bb }

  condition:
    any of them
}