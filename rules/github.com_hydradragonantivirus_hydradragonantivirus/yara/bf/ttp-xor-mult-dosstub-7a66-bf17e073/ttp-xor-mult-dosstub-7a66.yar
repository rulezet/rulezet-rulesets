rule TTP_XOR_MULT_DOSStub_7a66 {
  strings:
    $key_7a66 = { 2e 0e [2] 5a 16 [2] 1d 14 [2] 5a 05 [2] 14 09 [2] 18 03 [2] 0f 08 [2] 14 46 [2] 29 }

  condition:
    any of them
}