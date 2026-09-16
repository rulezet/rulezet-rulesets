rule TTP_XOR_MULT_DOSStub_e821 {
  strings:
    $key_e821 = { bc 49 [2] c8 51 [2] 8f 53 [2] c8 42 [2] 86 4e [2] 8a 44 [2] 9d 4f [2] 86 01 [2] bb }

  condition:
    any of them
}