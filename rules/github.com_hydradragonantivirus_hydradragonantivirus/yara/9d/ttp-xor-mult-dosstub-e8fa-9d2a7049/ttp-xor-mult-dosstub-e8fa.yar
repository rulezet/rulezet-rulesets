rule TTP_XOR_MULT_DOSStub_e8fa {
  strings:
    $key_e8fa = { bc 92 [2] c8 8a [2] 8f 88 [2] c8 99 [2] 86 95 [2] 8a 9f [2] 9d 94 [2] 86 da [2] bb }

  condition:
    any of them
}