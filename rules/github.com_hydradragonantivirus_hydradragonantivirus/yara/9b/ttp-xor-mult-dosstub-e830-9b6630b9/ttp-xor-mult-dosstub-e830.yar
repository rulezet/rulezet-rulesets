rule TTP_XOR_MULT_DOSStub_e830 {
  strings:
    $key_e830 = { bc 58 [2] c8 40 [2] 8f 42 [2] c8 53 [2] 86 5f [2] 8a 55 [2] 9d 5e [2] 86 10 [2] bb }

  condition:
    any of them
}