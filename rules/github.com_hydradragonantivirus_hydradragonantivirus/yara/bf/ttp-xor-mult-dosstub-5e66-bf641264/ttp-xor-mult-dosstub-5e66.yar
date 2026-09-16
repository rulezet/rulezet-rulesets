rule TTP_XOR_MULT_DOSStub_5e66 {
  strings:
    $key_5e66 = { 0a 0e [2] 7e 16 [2] 39 14 [2] 7e 05 [2] 30 09 [2] 3c 03 [2] 2b 08 [2] 30 46 [2] 0d }

  condition:
    any of them
}