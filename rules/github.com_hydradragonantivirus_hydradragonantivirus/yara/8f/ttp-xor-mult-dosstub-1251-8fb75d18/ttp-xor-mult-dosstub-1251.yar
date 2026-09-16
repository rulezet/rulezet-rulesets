rule TTP_XOR_MULT_DOSStub_1251 {
  strings:
    $key_1251 = { 46 39 [2] 32 21 [2] 75 23 [2] 32 32 [2] 7c 3e [2] 70 34 [2] 67 3f [2] 7c 71 [2] 41 }

  condition:
    any of them
}