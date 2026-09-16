rule TTP_XOR_MULT_DOSStub_6271 {
  strings:
    $key_6271 = { 36 19 [2] 42 01 [2] 05 03 [2] 42 12 [2] 0c 1e [2] 00 14 [2] 17 1f [2] 0c 51 [2] 31 }

  condition:
    any of them
}