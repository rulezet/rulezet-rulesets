rule TTP_XOR_MULT_DOSStub_5600 {
  strings:
    $key_5600 = { 02 68 [2] 76 70 [2] 31 72 [2] 76 63 [2] 38 6f [2] 34 65 [2] 23 6e [2] 38 20 [2] 05 }

  condition:
    any of them
}