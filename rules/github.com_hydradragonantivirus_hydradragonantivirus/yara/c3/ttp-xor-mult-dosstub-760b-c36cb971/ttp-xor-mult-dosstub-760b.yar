rule TTP_XOR_MULT_DOSStub_760b {
  strings:
    $key_760b = { 22 63 [2] 56 7b [2] 11 79 [2] 56 68 [2] 18 64 [2] 14 6e [2] 03 65 [2] 18 2b [2] 25 }

  condition:
    any of them
}