rule TTP_XOR_MULT_DOSStub_410b {
  strings:
    $key_410b = { 15 63 [2] 61 7b [2] 26 79 [2] 61 68 [2] 2f 64 [2] 23 6e [2] 34 65 [2] 2f 2b [2] 12 }

  condition:
    any of them
}