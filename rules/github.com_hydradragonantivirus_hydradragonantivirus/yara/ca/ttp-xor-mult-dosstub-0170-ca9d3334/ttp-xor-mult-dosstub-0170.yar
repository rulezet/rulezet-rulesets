rule TTP_XOR_MULT_DOSStub_0170 {
  strings:
    $key_0170 = { 55 18 [2] 21 00 [2] 66 02 [2] 21 13 [2] 6f 1f [2] 63 15 [2] 74 1e [2] 6f 50 [2] 52 }

  condition:
    any of them
}