rule TTP_XOR_MULT_DOSStub_e8eb {
  strings:
    $key_e8eb = { bc 83 [2] c8 9b [2] 8f 99 [2] c8 88 [2] 86 84 [2] 8a 8e [2] 9d 85 [2] 86 cb [2] bb }

  condition:
    any of them
}