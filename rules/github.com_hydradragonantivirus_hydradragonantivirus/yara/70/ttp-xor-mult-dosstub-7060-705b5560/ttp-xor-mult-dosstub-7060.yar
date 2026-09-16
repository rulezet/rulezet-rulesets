rule TTP_XOR_MULT_DOSStub_7060 {
  strings:
    $key_7060 = { 24 08 [2] 50 10 [2] 17 12 [2] 50 03 [2] 1e 0f [2] 12 05 [2] 05 0e [2] 1e 40 [2] 23 }

  condition:
    any of them
}