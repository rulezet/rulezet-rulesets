rule TTP_XOR_MULT_DOSStub_550b {
  strings:
    $key_550b = { 01 63 [2] 75 7b [2] 32 79 [2] 75 68 [2] 3b 64 [2] 37 6e [2] 20 65 [2] 3b 2b [2] 06 }

  condition:
    any of them
}