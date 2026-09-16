rule TTP_XOR_MULT_DOSStub_1731 {
  strings:
    $key_1731 = { 43 59 [2] 37 41 [2] 70 43 [2] 37 52 [2] 79 5e [2] 75 54 [2] 62 5f [2] 79 11 [2] 44 }

  condition:
    any of them
}