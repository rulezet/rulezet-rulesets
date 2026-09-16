rule TTP_XOR_MULT_DOSStub_44e0 {
  strings:
    $key_44e0 = { 10 88 [2] 64 90 [2] 23 92 [2] 64 83 [2] 2a 8f [2] 26 85 [2] 31 8e [2] 2a c0 [2] 17 }

  condition:
    any of them
}