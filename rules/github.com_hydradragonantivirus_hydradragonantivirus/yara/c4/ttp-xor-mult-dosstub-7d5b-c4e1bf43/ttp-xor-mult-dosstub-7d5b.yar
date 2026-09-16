rule TTP_XOR_MULT_DOSStub_7d5b {
  strings:
    $key_7d5b = { 29 33 [2] 5d 2b [2] 1a 29 [2] 5d 38 [2] 13 34 [2] 1f 3e [2] 08 35 [2] 13 7b [2] 2e }

  condition:
    any of them
}