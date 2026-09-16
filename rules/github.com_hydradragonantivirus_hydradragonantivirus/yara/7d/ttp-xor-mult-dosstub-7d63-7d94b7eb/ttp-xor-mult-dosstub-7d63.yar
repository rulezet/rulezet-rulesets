rule TTP_XOR_MULT_DOSStub_7d63 {
  strings:
    $key_7d63 = { 29 0b [2] 5d 13 [2] 1a 11 [2] 5d 00 [2] 13 0c [2] 1f 06 [2] 08 0d [2] 13 43 [2] 2e }

  condition:
    any of them
}