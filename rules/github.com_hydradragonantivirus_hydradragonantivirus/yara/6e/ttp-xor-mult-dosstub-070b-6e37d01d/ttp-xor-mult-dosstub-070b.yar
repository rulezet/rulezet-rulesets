rule TTP_XOR_MULT_DOSStub_070b {
  strings:
    $key_070b = { 53 63 [2] 27 7b [2] 60 79 [2] 27 68 [2] 69 64 [2] 65 6e [2] 72 65 [2] 69 2b [2] 54 }

  condition:
    any of them
}