rule TTP_XOR_MULT_DOSStub_e8e1 {
  strings:
    $key_e8e1 = { bc 89 [2] c8 91 [2] 8f 93 [2] c8 82 [2] 86 8e [2] 8a 84 [2] 9d 8f [2] 86 c1 [2] bb }

  condition:
    any of them
}