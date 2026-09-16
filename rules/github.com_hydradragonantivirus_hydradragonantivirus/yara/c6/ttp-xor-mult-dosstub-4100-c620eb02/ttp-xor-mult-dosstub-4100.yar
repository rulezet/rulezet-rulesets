rule TTP_XOR_MULT_DOSStub_4100 {
  strings:
    $key_4100 = { 15 68 [2] 61 70 [2] 26 72 [2] 61 63 [2] 2f 6f [2] 23 65 [2] 34 6e [2] 2f 20 [2] 12 }

  condition:
    any of them
}