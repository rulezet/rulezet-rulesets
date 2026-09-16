rule TTP_XOR_MULT_DOSStub_6147 {
  strings:
    $key_6147 = { 35 2f [2] 41 37 [2] 06 35 [2] 41 24 [2] 0f 28 [2] 03 22 [2] 14 29 [2] 0f 67 [2] 32 }

  condition:
    any of them
}