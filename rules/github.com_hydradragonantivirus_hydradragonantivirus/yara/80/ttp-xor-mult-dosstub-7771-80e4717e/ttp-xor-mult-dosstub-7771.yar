rule TTP_XOR_MULT_DOSStub_7771 {
  strings:
    $key_7771 = { 23 19 [2] 57 01 [2] 10 03 [2] 57 12 [2] 19 1e [2] 15 14 [2] 02 1f [2] 19 51 [2] 24 }

  condition:
    any of them
}