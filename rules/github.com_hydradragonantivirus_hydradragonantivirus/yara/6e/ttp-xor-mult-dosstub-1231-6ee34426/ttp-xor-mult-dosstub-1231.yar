rule TTP_XOR_MULT_DOSStub_1231 {
  strings:
    $key_1231 = { 46 59 [2] 32 41 [2] 75 43 [2] 32 52 [2] 7c 5e [2] 70 54 [2] 67 5f [2] 7c 11 [2] 41 }

  condition:
    any of them
}