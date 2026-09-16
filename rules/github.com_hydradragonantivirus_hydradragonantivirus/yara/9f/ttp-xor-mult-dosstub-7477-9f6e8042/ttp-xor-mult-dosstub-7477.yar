rule TTP_XOR_MULT_DOSStub_7477 {
  strings:
    $key_7477 = { 20 1f [2] 54 07 [2] 13 05 [2] 54 14 [2] 1a 18 [2] 16 12 [2] 01 19 [2] 1a 57 [2] 27 }

  condition:
    any of them
}