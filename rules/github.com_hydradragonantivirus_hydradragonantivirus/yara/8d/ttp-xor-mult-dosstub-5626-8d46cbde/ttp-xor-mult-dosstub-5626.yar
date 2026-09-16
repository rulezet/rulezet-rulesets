rule TTP_XOR_MULT_DOSStub_5626 {
  strings:
    $key_5626 = { 02 4e [2] 76 56 [2] 31 54 [2] 76 45 [2] 38 49 [2] 34 43 [2] 23 48 [2] 38 06 [2] 05 }

  condition:
    any of them
}