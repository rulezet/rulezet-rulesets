rule TTP_XOR_MULT_DOSStub_e850 {
  strings:
    $key_e850 = { bc 38 [2] c8 20 [2] 8f 22 [2] c8 33 [2] 86 3f [2] 8a 35 [2] 9d 3e [2] 86 70 [2] bb }

  condition:
    any of them
}