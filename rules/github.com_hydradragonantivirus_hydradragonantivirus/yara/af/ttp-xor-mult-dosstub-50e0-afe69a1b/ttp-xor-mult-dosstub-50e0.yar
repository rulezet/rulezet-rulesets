rule TTP_XOR_MULT_DOSStub_50e0 {
  strings:
    $key_50e0 = { 04 88 [2] 70 90 [2] 37 92 [2] 70 83 [2] 3e 8f [2] 32 85 [2] 25 8e [2] 3e c0 [2] 03 }

  condition:
    any of them
}