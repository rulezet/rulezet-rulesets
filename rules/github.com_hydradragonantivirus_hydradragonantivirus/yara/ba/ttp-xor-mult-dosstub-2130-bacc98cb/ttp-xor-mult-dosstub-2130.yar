rule TTP_XOR_MULT_DOSStub_2130 {
  strings:
    $key_2130 = { 75 58 [2] 01 40 [2] 46 42 [2] 01 53 [2] 4f 5f [2] 43 55 [2] 54 5e [2] 4f 10 [2] 72 }

  condition:
    any of them
}