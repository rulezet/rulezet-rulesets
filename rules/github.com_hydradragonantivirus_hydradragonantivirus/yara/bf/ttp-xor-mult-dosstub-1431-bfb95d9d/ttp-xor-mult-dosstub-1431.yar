rule TTP_XOR_MULT_DOSStub_1431 {
  strings:
    $key_1431 = { 40 59 [2] 34 41 [2] 73 43 [2] 34 52 [2] 7a 5e [2] 76 54 [2] 61 5f [2] 7a 11 [2] 47 }

  condition:
    any of them
}