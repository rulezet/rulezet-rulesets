rule TTP_XOR_MULT_DOSStub_4c6b {
  strings:
    $key_4c6b = { 18 03 [2] 6c 1b [2] 2b 19 [2] 6c 08 [2] 22 04 [2] 2e 0e [2] 39 05 [2] 22 4b [2] 1f }

  condition:
    any of them
}