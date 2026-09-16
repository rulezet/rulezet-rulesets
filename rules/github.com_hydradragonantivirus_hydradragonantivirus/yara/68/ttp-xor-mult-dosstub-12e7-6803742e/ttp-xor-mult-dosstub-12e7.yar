rule TTP_XOR_MULT_DOSStub_12e7 {
  strings:
    $key_12e7 = { 46 8f [2] 32 97 [2] 75 95 [2] 32 84 [2] 7c 88 [2] 70 82 [2] 67 89 [2] 7c c7 [2] 41 }

  condition:
    any of them
}