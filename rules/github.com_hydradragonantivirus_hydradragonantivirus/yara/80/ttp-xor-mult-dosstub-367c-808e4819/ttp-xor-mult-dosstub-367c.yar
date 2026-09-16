rule TTP_XOR_MULT_DOSStub_367c {
  strings:
    $key_367c = { 62 14 [2] 16 0c [2] 51 0e [2] 16 1f [2] 58 13 [2] 54 19 [2] 43 12 [2] 58 5c [2] 65 }

  condition:
    any of them
}