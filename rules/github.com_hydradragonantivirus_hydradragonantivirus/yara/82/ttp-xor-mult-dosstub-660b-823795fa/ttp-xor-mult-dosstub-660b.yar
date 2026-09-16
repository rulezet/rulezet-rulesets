rule TTP_XOR_MULT_DOSStub_660b {
  strings:
    $key_660b = { 32 63 [2] 46 7b [2] 01 79 [2] 46 68 [2] 08 64 [2] 04 6e [2] 13 65 [2] 08 2b [2] 35 }

  condition:
    any of them
}