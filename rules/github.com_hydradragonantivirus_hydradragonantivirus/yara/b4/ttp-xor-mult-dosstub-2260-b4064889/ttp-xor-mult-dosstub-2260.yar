rule TTP_XOR_MULT_DOSStub_2260 {
  strings:
    $key_2260 = { 76 08 [2] 02 10 [2] 45 12 [2] 02 03 [2] 4c 0f [2] 40 05 [2] 57 0e [2] 4c 40 [2] 71 }

  condition:
    any of them
}