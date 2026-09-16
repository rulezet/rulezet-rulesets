rule TTP_XOR_MULT_DOSStub_e837 {
  strings:
    $key_e837 = { bc 5f [2] c8 47 [2] 8f 45 [2] c8 54 [2] 86 58 [2] 8a 52 [2] 9d 59 [2] 86 17 [2] bb }

  condition:
    any of them
}