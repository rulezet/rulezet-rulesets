rule TTP_XOR_MULT_DOSStub_e844 {
  strings:
    $key_e844 = { bc 2c [2] c8 34 [2] 8f 36 [2] c8 27 [2] 86 2b [2] 8a 21 [2] 9d 2a [2] 86 64 [2] bb }

  condition:
    any of them
}