rule TTP_XOR_MULT_DOSStub_3b66 {
  strings:
    $key_3b66 = { 6f 0e [2] 1b 16 [2] 5c 14 [2] 1b 05 [2] 55 09 [2] 59 03 [2] 4e 08 [2] 55 46 [2] 68 }

  condition:
    any of them
}