rule TTP_XOR_MULT_DOSStub_4c0b {
  strings:
    $key_4c0b = { 18 63 [2] 6c 7b [2] 2b 79 [2] 6c 68 [2] 22 64 [2] 2e 6e [2] 39 65 [2] 22 2b [2] 1f }

  condition:
    any of them
}