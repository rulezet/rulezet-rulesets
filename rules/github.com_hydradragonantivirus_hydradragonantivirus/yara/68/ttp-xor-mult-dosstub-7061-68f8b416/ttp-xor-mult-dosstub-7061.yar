rule TTP_XOR_MULT_DOSStub_7061 {
  strings:
    $key_7061 = { 24 09 [2] 50 11 [2] 17 13 [2] 50 02 [2] 1e 0e [2] 12 04 [2] 05 0f [2] 1e 41 [2] 23 }

  condition:
    any of them
}