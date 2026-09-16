rule TTP_XOR_MULT_DOSStub_e8ea {
  strings:
    $key_e8ea = { bc 82 [2] c8 9a [2] 8f 98 [2] c8 89 [2] 86 85 [2] 8a 8f [2] 9d 84 [2] 86 ca [2] bb }

  condition:
    any of them
}