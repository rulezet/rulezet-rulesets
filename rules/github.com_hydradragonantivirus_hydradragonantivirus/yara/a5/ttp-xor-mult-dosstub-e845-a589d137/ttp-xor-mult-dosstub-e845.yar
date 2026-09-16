rule TTP_XOR_MULT_DOSStub_e845 {
  strings:
    $key_e845 = { bc 2d [2] c8 35 [2] 8f 37 [2] c8 26 [2] 86 2a [2] 8a 20 [2] 9d 2b [2] 86 65 [2] bb }

  condition:
    any of them
}