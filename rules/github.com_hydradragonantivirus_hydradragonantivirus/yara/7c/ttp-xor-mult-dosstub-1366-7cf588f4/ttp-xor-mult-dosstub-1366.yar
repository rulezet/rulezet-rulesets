rule TTP_XOR_MULT_DOSStub_1366 {
  strings:
    $key_1366 = { 47 0e [2] 33 16 [2] 74 14 [2] 33 05 [2] 7d 09 [2] 71 03 [2] 66 08 [2] 7d 46 [2] 40 }

  condition:
    any of them
}