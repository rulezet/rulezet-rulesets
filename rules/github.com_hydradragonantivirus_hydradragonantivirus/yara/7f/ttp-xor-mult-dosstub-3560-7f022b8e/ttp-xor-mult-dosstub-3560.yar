rule TTP_XOR_MULT_DOSStub_3560 {
  strings:
    $key_3560 = { 61 08 [2] 15 10 [2] 52 12 [2] 15 03 [2] 5b 0f [2] 57 05 [2] 40 0e [2] 5b 40 [2] 66 }

  condition:
    any of them
}