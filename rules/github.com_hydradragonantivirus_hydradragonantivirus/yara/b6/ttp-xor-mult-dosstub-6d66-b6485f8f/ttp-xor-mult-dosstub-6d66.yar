rule TTP_XOR_MULT_DOSStub_6d66 {
  strings:
    $key_6d66 = { 39 0e [2] 4d 16 [2] 0a 14 [2] 4d 05 [2] 03 09 [2] 0f 03 [2] 18 08 [2] 03 46 [2] 3e }

  condition:
    any of them
}