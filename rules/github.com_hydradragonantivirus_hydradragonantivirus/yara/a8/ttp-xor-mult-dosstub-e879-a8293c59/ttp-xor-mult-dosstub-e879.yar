rule TTP_XOR_MULT_DOSStub_e879 {
  strings:
    $key_e879 = { bc 11 [2] c8 09 [2] 8f 0b [2] c8 1a [2] 86 16 [2] 8a 1c [2] 9d 17 [2] 86 59 [2] bb }

  condition:
    any of them
}