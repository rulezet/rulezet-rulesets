rule TTP_XOR_MULT_DOSStub_36e6 {
  strings:
    $key_36e6 = { 62 8e [2] 16 96 [2] 51 94 [2] 16 85 [2] 58 89 [2] 54 83 [2] 43 88 [2] 58 c6 [2] 65 }

  condition:
    any of them
}