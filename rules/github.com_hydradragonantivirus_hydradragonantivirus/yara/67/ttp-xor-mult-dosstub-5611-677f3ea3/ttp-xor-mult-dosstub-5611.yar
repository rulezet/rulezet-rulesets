rule TTP_XOR_MULT_DOSStub_5611 {
  strings:
    $key_5611 = { 02 79 [2] 76 61 [2] 31 63 [2] 76 72 [2] 38 7e [2] 34 74 [2] 23 7f [2] 38 31 [2] 05 }

  condition:
    any of them
}