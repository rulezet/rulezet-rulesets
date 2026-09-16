rule TTP_XOR_MULT_DOSStub_7d2b {
  strings:
    $key_7d2b = { 29 43 [2] 5d 5b [2] 1a 59 [2] 5d 48 [2] 13 44 [2] 1f 4e [2] 08 45 [2] 13 0b [2] 2e }

  condition:
    any of them
}