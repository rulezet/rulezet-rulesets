rule TTP_XOR_MULT_DOSStub_3571 {
  strings:
    $key_3571 = { 61 19 [2] 15 01 [2] 52 03 [2] 15 12 [2] 5b 1e [2] 57 14 [2] 40 1f [2] 5b 51 [2] 66 }

  condition:
    any of them
}