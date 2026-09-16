rule TTP_XOR_MULT_DOSStub_4d66 {
  strings:
    $key_4d66 = { 19 0e [2] 6d 16 [2] 2a 14 [2] 6d 05 [2] 23 09 [2] 2f 03 [2] 38 08 [2] 23 46 [2] 1e }

  condition:
    any of them
}