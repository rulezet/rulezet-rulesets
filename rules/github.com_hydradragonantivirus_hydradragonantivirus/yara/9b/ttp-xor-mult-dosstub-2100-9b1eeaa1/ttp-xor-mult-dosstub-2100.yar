rule TTP_XOR_MULT_DOSStub_2100 {
  strings:
    $key_2100 = { 75 68 [2] 01 70 [2] 46 72 [2] 01 63 [2] 4f 6f [2] 43 65 [2] 54 6e [2] 4f 20 [2] 72 }

  condition:
    any of them
}