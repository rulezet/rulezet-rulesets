rule TTP_XOR_MULT_DOSStub_70e0 {
  strings:
    $key_70e0 = { 24 88 [2] 50 90 [2] 17 92 [2] 50 83 [2] 1e 8f [2] 12 85 [2] 05 8e [2] 1e c0 [2] 23 }

  condition:
    any of them
}