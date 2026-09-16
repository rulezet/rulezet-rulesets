rule TTP_XOR_MULT_DOSStub_0e66 {
  strings:
    $key_0e66 = { 5a 0e [2] 2e 16 [2] 69 14 [2] 2e 05 [2] 60 09 [2] 6c 03 [2] 7b 08 [2] 60 46 [2] 5d }

  condition:
    any of them
}