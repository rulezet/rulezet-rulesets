rule TTP_XOR_MULT_DOSStub_771b {
  strings:
    $key_771b = { 23 73 [2] 57 6b [2] 10 69 [2] 57 78 [2] 19 74 [2] 15 7e [2] 02 75 [2] 19 3b [2] 24 }

  condition:
    any of them
}