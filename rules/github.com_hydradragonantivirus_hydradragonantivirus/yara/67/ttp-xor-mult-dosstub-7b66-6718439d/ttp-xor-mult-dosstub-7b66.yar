rule TTP_XOR_MULT_DOSStub_7b66 {
  strings:
    $key_7b66 = { 2f 0e [2] 5b 16 [2] 1c 14 [2] 5b 05 [2] 15 09 [2] 19 03 [2] 0e 08 [2] 15 46 [2] 28 }

  condition:
    any of them
}