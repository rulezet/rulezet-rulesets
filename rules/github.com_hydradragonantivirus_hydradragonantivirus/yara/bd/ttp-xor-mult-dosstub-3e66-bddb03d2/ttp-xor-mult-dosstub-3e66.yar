rule TTP_XOR_MULT_DOSStub_3e66 {
  strings:
    $key_3e66 = { 6a 0e [2] 1e 16 [2] 59 14 [2] 1e 05 [2] 50 09 [2] 5c 03 [2] 4b 08 [2] 50 46 [2] 6d }

  condition:
    any of them
}