rule TTP_XOR_MULT_DOSStub_7c3b {
  strings:
    $key_7c3b = { 28 53 [2] 5c 4b [2] 1b 49 [2] 5c 58 [2] 12 54 [2] 1e 5e [2] 09 55 [2] 12 1b [2] 2f }

  condition:
    any of them
}