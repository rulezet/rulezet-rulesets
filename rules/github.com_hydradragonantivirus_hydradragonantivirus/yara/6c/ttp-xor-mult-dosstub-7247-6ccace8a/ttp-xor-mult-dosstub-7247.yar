rule TTP_XOR_MULT_DOSStub_7247 {
  strings:
    $key_7247 = { 26 2f [2] 52 37 [2] 15 35 [2] 52 24 [2] 1c 28 [2] 10 22 [2] 07 29 [2] 1c 67 [2] 21 }

  condition:
    any of them
}