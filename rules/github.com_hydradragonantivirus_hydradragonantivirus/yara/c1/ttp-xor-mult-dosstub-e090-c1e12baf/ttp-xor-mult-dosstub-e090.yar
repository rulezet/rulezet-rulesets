rule TTP_XOR_MULT_DOSStub_e090 {
  strings:
    $key_e090 = { b4 f8 [2] c0 e0 [2] 87 e2 [2] c0 f3 [2] 8e ff [2] 82 f5 [2] 95 fe [2] 8e b0 [2] b3 }

  condition:
    any of them
}