rule TTP_XOR_MULT_DOSStub_36e0 {
  strings:
    $key_36e0 = { 62 88 [2] 16 90 [2] 51 92 [2] 16 83 [2] 58 8f [2] 54 85 [2] 43 8e [2] 58 c0 [2] 65 }

  condition:
    any of them
}