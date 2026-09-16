rule TTP_XOR_MULT_DOSStub_1241 {
  strings:
    $key_1241 = { 46 29 [2] 32 31 [2] 75 33 [2] 32 22 [2] 7c 2e [2] 70 24 [2] 67 2f [2] 7c 61 [2] 41 }

  condition:
    any of them
}