rule TTP_XOR_MULT_DOSStub_e8e5 {
  strings:
    $key_e8e5 = { bc 8d [2] c8 95 [2] 8f 97 [2] c8 86 [2] 86 8a [2] 8a 80 [2] 9d 8b [2] 86 c5 [2] bb }

  condition:
    any of them
}