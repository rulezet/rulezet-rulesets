rule TTP_XOR_MULT_DOSStub_7d04 {
  strings:
    $key_7d04 = { 29 6c [2] 5d 74 [2] 1a 76 [2] 5d 67 [2] 13 6b [2] 1f 61 [2] 08 6a [2] 13 24 [2] 2e }

  condition:
    any of them
}