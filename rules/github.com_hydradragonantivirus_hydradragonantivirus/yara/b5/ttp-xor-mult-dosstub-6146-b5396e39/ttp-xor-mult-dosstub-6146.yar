rule TTP_XOR_MULT_DOSStub_6146 {
  strings:
    $key_6146 = { 35 2e [2] 41 36 [2] 06 34 [2] 41 25 [2] 0f 29 [2] 03 23 [2] 14 28 [2] 0f 66 [2] 32 }

  condition:
    any of them
}