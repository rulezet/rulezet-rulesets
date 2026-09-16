rule TTP_XOR_MULT_DOSStub_e8e7 {
  strings:
    $key_e8e7 = { bc 8f [2] c8 97 [2] 8f 95 [2] c8 84 [2] 86 88 [2] 8a 82 [2] 9d 89 [2] 86 c7 [2] bb }

  condition:
    any of them
}