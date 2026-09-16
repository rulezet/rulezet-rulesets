rule TTP_XOR_MULT_DOSStub_310b {
  strings:
    $key_310b = { 65 63 [2] 11 7b [2] 56 79 [2] 11 68 [2] 5f 64 [2] 53 6e [2] 44 65 [2] 5f 2b [2] 62 }

  condition:
    any of them
}