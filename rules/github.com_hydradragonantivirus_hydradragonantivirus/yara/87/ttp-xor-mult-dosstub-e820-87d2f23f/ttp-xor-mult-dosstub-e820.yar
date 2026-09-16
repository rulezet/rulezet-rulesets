rule TTP_XOR_MULT_DOSStub_e820 {
  strings:
    $key_e820 = { bc 48 [2] c8 50 [2] 8f 52 [2] c8 43 [2] 86 4f [2] 8a 45 [2] 9d 4e [2] 86 00 [2] bb }

  condition:
    any of them
}