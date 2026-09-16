rule TTP_XOR_MULT_DOSStub_460b {
  strings:
    $key_460b = { 12 63 [2] 66 7b [2] 21 79 [2] 66 68 [2] 28 64 [2] 24 6e [2] 33 65 [2] 28 2b [2] 15 }

  condition:
    any of them
}