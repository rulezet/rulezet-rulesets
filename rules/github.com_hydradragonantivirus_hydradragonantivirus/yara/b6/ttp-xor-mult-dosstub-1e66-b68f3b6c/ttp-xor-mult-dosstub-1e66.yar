rule TTP_XOR_MULT_DOSStub_1e66 {
  strings:
    $key_1e66 = { 4a 0e [2] 3e 16 [2] 79 14 [2] 3e 05 [2] 70 09 [2] 7c 03 [2] 6b 08 [2] 70 46 [2] 4d }

  condition:
    any of them
}