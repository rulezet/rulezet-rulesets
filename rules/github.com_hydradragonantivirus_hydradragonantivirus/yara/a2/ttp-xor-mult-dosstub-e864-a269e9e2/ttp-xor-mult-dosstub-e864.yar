rule TTP_XOR_MULT_DOSStub_e864 {
  strings:
    $key_e864 = { bc 0c [2] c8 14 [2] 8f 16 [2] c8 07 [2] 86 0b [2] 8a 01 [2] 9d 0a [2] 86 44 [2] bb }

  condition:
    any of them
}