rule TTP_XOR_MULT_DOSStub_7ce0 {
  strings:
    $key_7ce0 = { 28 88 [2] 5c 90 [2] 1b 92 [2] 5c 83 [2] 12 8f [2] 1e 85 [2] 09 8e [2] 12 c0 [2] 2f }

  condition:
    any of them
}