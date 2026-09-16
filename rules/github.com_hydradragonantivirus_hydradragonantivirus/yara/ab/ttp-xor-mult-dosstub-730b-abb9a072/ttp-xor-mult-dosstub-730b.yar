rule TTP_XOR_MULT_DOSStub_730b {
  strings:
    $key_730b = { 27 63 [2] 53 7b [2] 14 79 [2] 53 68 [2] 1d 64 [2] 11 6e [2] 06 65 [2] 1d 2b [2] 20 }

  condition:
    any of them
}