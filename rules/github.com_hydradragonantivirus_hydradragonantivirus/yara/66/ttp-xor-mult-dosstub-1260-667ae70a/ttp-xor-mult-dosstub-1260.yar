rule TTP_XOR_MULT_DOSStub_1260 {
  strings:
    $key_1260 = { 46 08 [2] 32 10 [2] 75 12 [2] 32 03 [2] 7c 0f [2] 70 05 [2] 67 0e [2] 7c 40 [2] 41 }

  condition:
    any of them
}