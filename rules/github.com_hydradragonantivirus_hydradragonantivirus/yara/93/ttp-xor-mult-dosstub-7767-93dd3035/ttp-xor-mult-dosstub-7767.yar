rule TTP_XOR_MULT_DOSStub_7767 {
  strings:
    $key_7767 = { 23 0f [2] 57 17 [2] 10 15 [2] 57 04 [2] 19 08 [2] 15 02 [2] 02 09 [2] 19 47 [2] 24 }

  condition:
    any of them
}