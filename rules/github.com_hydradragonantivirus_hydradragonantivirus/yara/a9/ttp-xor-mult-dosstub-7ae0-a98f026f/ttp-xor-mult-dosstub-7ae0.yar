rule TTP_XOR_MULT_DOSStub_7ae0 {
  strings:
    $key_7ae0 = { 2e 88 [2] 5a 90 [2] 1d 92 [2] 5a 83 [2] 14 8f [2] 18 85 [2] 0f 8e [2] 14 c0 [2] 29 }

  condition:
    any of them
}