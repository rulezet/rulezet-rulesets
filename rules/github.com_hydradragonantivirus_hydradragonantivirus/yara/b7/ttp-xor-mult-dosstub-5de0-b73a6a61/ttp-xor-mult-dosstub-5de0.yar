rule TTP_XOR_MULT_DOSStub_5de0 {
  strings:
    $key_5de0 = { 09 88 [2] 7d 90 [2] 3a 92 [2] 7d 83 [2] 33 8f [2] 3f 85 [2] 28 8e [2] 33 c0 [2] 0e }

  condition:
    any of them
}