rule TTP_XOR_MULT_DOSStub_367d {
  strings:
    $key_367d = { 62 15 [2] 16 0d [2] 51 0f [2] 16 1e [2] 58 12 [2] 54 18 [2] 43 13 [2] 58 5d [2] 65 }

  condition:
    any of them
}