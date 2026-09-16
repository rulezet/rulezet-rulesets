rule TTP_XOR_MULT_DOSStub_e874 {
  strings:
    $key_e874 = { bc 1c [2] c8 04 [2] 8f 06 [2] c8 17 [2] 86 1b [2] 8a 11 [2] 9d 1a [2] 86 54 [2] bb }

  condition:
    any of them
}