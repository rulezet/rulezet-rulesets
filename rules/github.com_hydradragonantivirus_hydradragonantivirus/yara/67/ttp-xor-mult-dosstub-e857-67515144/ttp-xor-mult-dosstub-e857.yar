rule TTP_XOR_MULT_DOSStub_e857 {
  strings:
    $key_e857 = { bc 3f [2] c8 27 [2] 8f 25 [2] c8 34 [2] 86 38 [2] 8a 32 [2] 9d 39 [2] 86 77 [2] bb }

  condition:
    any of them
}