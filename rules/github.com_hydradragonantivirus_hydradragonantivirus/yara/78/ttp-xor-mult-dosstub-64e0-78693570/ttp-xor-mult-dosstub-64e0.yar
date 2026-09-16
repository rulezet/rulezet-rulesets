rule TTP_XOR_MULT_DOSStub_64e0 {
  strings:
    $key_64e0 = { 30 88 [2] 44 90 [2] 03 92 [2] 44 83 [2] 0a 8f [2] 06 85 [2] 11 8e [2] 0a c0 [2] 37 }

  condition:
    any of them
}