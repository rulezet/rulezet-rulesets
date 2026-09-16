rule TTP_XOR_MULT_DOSStub_e865 {
  strings:
    $key_e865 = { bc 0d [2] c8 15 [2] 8f 17 [2] c8 06 [2] 86 0a [2] 8a 00 [2] 9d 0b [2] 86 45 [2] bb }

  condition:
    any of them
}