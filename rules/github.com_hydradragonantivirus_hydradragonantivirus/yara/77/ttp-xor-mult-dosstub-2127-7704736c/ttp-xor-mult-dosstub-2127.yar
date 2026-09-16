rule TTP_XOR_MULT_DOSStub_2127 {
  strings:
    $key_2127 = { 75 4f [2] 01 57 [2] 46 55 [2] 01 44 [2] 4f 48 [2] 43 42 [2] 54 49 [2] 4f 07 [2] 72 }

  condition:
    any of them
}