rule TTP_XOR_MULT_DOSStub_220b {
  strings:
    $key_220b = { 76 63 [2] 02 7b [2] 45 79 [2] 02 68 [2] 4c 64 [2] 40 6e [2] 57 65 [2] 4c 2b [2] 71 }

  condition:
    any of them
}