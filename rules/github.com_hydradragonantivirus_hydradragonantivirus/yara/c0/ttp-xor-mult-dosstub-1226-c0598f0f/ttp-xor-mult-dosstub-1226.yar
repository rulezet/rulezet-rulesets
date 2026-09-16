rule TTP_XOR_MULT_DOSStub_1226 {
  strings:
    $key_1226 = { 46 4e [2] 32 56 [2] 75 54 [2] 32 45 [2] 7c 49 [2] 70 43 [2] 67 48 [2] 7c 06 [2] 41 }

  condition:
    any of them
}