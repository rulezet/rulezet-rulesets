rule TTP_XOR_MULT_DOSStub_4171 {
  strings:
    $key_4171 = { 15 19 [2] 61 01 [2] 26 03 [2] 61 12 [2] 2f 1e [2] 23 14 [2] 34 1f [2] 2f 51 [2] 12 }

  condition:
    any of them
}