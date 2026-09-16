rule TTP_XOR_MULT_DOSStub_e863 {
  strings:
    $key_e863 = { bc 0b [2] c8 13 [2] 8f 11 [2] c8 00 [2] 86 0c [2] 8a 06 [2] 9d 0d [2] 86 43 [2] bb }

  condition:
    any of them
}