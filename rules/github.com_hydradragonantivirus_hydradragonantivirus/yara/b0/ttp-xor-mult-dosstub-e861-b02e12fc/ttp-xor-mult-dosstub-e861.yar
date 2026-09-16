rule TTP_XOR_MULT_DOSStub_e861 {
  strings:
    $key_e861 = { bc 09 [2] c8 11 [2] 8f 13 [2] c8 02 [2] 86 0e [2] 8a 04 [2] 9d 0f [2] 86 41 [2] bb }

  condition:
    any of them
}