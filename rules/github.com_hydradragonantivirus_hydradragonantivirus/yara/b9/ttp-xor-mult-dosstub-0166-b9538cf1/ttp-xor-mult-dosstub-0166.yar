rule TTP_XOR_MULT_DOSStub_0166 {
  strings:
    $key_0166 = { 55 0e [2] 21 16 [2] 66 14 [2] 21 05 [2] 6f 09 [2] 63 03 [2] 74 08 [2] 6f 46 [2] 52 }

  condition:
    any of them
}