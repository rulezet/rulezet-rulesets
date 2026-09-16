rule TTP_XOR_MULT_DOSStub_7d1b {
  strings:
    $key_7d1b = { 29 73 [2] 5d 6b [2] 1a 69 [2] 5d 78 [2] 13 74 [2] 1f 7e [2] 08 75 [2] 13 3b [2] 2e }

  condition:
    any of them
}