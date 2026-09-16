rule TTP_XOR_MULT_DOSStub_e836 {
  strings:
    $key_e836 = { bc 5e [2] c8 46 [2] 8f 44 [2] c8 55 [2] 86 59 [2] 8a 53 [2] 9d 58 [2] 86 16 [2] bb }

  condition:
    any of them
}