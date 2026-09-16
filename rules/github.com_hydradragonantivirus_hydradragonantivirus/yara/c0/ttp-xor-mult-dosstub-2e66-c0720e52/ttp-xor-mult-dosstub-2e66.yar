rule TTP_XOR_MULT_DOSStub_2e66 {
  strings:
    $key_2e66 = { 7a 0e [2] 0e 16 [2] 49 14 [2] 0e 05 [2] 40 09 [2] 4c 03 [2] 5b 08 [2] 40 46 [2] 7d }

  condition:
    any of them
}