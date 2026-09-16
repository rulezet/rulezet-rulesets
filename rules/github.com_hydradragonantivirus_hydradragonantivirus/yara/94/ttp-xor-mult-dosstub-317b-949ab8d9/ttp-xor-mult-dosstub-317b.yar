rule TTP_XOR_MULT_DOSStub_317b {
  strings:
    $key_317b = { 65 13 [2] 11 0b [2] 56 09 [2] 11 18 [2] 5f 14 [2] 53 1e [2] 44 15 [2] 5f 5b [2] 62 }

  condition:
    any of them
}