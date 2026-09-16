rule TTP_XOR_MULT_DOSStub_12e0 {
  strings:
    $key_12e0 = { 46 88 [2] 32 90 [2] 75 92 [2] 32 83 [2] 7c 8f [2] 70 85 [2] 67 8e [2] 7c c0 [2] 41 }

  condition:
    any of them
}