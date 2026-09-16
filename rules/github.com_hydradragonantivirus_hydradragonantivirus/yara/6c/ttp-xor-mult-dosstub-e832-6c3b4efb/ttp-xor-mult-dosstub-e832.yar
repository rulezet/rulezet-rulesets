rule TTP_XOR_MULT_DOSStub_e832 {
  strings:
    $key_e832 = { bc 5a [2] c8 42 [2] 8f 40 [2] c8 51 [2] 86 5d [2] 8a 57 [2] 9d 5c [2] 86 12 [2] bb }

  condition:
    any of them
}