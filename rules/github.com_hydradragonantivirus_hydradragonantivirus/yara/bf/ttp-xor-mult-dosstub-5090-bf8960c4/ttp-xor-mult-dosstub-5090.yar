rule TTP_XOR_MULT_DOSStub_5090 {
  strings:
    $key_5090 = { 04 f8 [2] 70 e0 [2] 37 e2 [2] 70 f3 [2] 3e ff [2] 32 f5 [2] 25 fe [2] 3e b0 [2] 03 }

  condition:
    any of them
}