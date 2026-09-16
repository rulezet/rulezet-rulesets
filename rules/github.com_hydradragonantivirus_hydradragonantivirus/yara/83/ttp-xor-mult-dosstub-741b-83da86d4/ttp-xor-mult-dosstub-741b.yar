rule TTP_XOR_MULT_DOSStub_741b {
  strings:
    $key_741b = { 20 73 [2] 54 6b [2] 13 69 [2] 54 78 [2] 1a 74 [2] 16 7e [2] 01 75 [2] 1a 3b [2] 27 }

  condition:
    any of them
}