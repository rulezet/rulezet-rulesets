rule TTP_XOR_MULT_DOSStub_710b {
  strings:
    $key_710b = { 25 63 [2] 51 7b [2] 16 79 [2] 51 68 [2] 1f 64 [2] 13 6e [2] 04 65 [2] 1f 2b [2] 22 }

  condition:
    any of them
}