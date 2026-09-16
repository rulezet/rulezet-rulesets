rule TTP_XOR_MULT_DOSStub_47e0 {
  strings:
    $key_47e0 = { 13 88 [2] 67 90 [2] 20 92 [2] 67 83 [2] 29 8f [2] 25 85 [2] 32 8e [2] 29 c0 [2] 14 }

  condition:
    any of them
}