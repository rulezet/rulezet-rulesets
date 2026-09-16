rule TTP_XOR_MULT_DOSStub_e870 {
  strings:
    $key_e870 = { bc 18 [2] c8 00 [2] 8f 02 [2] c8 13 [2] 86 1f [2] 8a 15 [2] 9d 1e [2] 86 50 [2] bb }

  condition:
    any of them
}