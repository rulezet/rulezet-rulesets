rule TTP_XOR_MULT_DOSStub_2120 {
  strings:
    $key_2120 = { 75 48 [2] 01 50 [2] 46 52 [2] 01 43 [2] 4f 4f [2] 43 45 [2] 54 4e [2] 4f 00 [2] 72 }

  condition:
    any of them
}