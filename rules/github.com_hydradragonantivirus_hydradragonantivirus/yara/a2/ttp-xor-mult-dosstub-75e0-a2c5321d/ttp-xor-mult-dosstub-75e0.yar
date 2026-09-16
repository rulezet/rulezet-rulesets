rule TTP_XOR_MULT_DOSStub_75e0 {
  strings:
    $key_75e0 = { 21 88 [2] 55 90 [2] 12 92 [2] 55 83 [2] 1b 8f [2] 17 85 [2] 00 8e [2] 1b c0 [2] 26 }

  condition:
    any of them
}