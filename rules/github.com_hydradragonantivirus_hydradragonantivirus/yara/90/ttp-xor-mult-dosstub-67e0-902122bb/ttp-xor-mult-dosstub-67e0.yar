rule TTP_XOR_MULT_DOSStub_67e0 {
  strings:
    $key_67e0 = { 33 88 [2] 47 90 [2] 00 92 [2] 47 83 [2] 09 8f [2] 05 85 [2] 12 8e [2] 09 c0 [2] 34 }

  condition:
    any of them
}