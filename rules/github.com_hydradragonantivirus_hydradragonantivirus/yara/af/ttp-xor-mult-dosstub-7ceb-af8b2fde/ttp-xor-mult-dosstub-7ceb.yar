rule TTP_XOR_MULT_DOSStub_7ceb {
  strings:
    $key_7ceb = { 28 83 [2] 5c 9b [2] 1b 99 [2] 5c 88 [2] 12 84 [2] 1e 8e [2] 09 85 [2] 12 cb [2] 2f }

  condition:
    any of them
}