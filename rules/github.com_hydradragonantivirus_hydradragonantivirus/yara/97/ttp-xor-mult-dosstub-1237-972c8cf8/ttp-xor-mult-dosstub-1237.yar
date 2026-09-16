rule TTP_XOR_MULT_DOSStub_1237 {
  strings:
    $key_1237 = { 46 5f [2] 32 47 [2] 75 45 [2] 32 54 [2] 7c 58 [2] 70 52 [2] 67 59 [2] 7c 17 [2] 41 }

  condition:
    any of them
}