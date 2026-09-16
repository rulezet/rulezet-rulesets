rule TTP_XOR_MULT_DOSStub_6376 {
  strings:
    $key_6376 = { 37 1e [2] 43 06 [2] 04 04 [2] 43 15 [2] 0d 19 [2] 01 13 [2] 16 18 [2] 0d 56 [2] 30 }

  condition:
    any of them
}