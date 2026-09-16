rule TTP_XOR_MULT_DOSStub_7c2b {
  strings:
    $key_7c2b = { 28 43 [2] 5c 5b [2] 1b 59 [2] 5c 48 [2] 12 44 [2] 1e 4e [2] 09 45 [2] 12 0b [2] 2f }

  condition:
    any of them
}