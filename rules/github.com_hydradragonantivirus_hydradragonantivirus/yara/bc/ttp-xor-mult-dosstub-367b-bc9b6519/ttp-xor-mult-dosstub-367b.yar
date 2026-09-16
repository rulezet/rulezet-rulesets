rule TTP_XOR_MULT_DOSStub_367b {
  strings:
    $key_367b = { 62 13 [2] 16 0b [2] 51 09 [2] 16 18 [2] 58 14 [2] 54 1e [2] 43 15 [2] 58 5b [2] 65 }

  condition:
    any of them
}