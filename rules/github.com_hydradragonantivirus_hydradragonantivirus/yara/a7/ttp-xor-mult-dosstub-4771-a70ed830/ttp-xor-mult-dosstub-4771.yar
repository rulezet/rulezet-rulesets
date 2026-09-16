rule TTP_XOR_MULT_DOSStub_4771 {
  strings:
    $key_4771 = { 13 19 [2] 67 01 [2] 20 03 [2] 67 12 [2] 29 1e [2] 25 14 [2] 32 1f [2] 29 51 [2] 14 }

  condition:
    any of them
}