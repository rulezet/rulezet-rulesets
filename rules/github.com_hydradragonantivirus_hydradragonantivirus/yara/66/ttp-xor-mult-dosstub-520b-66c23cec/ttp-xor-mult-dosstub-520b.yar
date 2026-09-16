rule TTP_XOR_MULT_DOSStub_520b {
  strings:
    $key_520b = { 06 63 [2] 72 7b [2] 35 79 [2] 72 68 [2] 3c 64 [2] 30 6e [2] 27 65 [2] 3c 2b [2] 01 }

  condition:
    any of them
}