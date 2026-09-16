rule TTP_XOR_MULT_DOSStub_1660 {
  strings:
    $key_1660 = { 42 08 [2] 36 10 [2] 71 12 [2] 36 03 [2] 78 0f [2] 74 05 [2] 63 0e [2] 78 40 [2] 45 }

  condition:
    any of them
}