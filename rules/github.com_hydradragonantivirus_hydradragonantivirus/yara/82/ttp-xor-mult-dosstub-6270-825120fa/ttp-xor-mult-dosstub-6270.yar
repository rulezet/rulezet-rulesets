rule TTP_XOR_MULT_DOSStub_6270 {
  strings:
    $key_6270 = { 36 18 [2] 42 00 [2] 05 02 [2] 42 13 [2] 0c 1f [2] 00 15 [2] 17 1e [2] 0c 50 [2] 31 }

  condition:
    any of them
}