rule TTP_XOR_MULT_DOSStub_4c2b {
  strings:
    $key_4c2b = { 18 43 [2] 6c 5b [2] 2b 59 [2] 6c 48 [2] 22 44 [2] 2e 4e [2] 39 45 [2] 22 0b [2] 1f }

  condition:
    any of them
}