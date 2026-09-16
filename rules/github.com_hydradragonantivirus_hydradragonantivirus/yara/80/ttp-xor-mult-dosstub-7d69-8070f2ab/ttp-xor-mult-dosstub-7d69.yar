rule TTP_XOR_MULT_DOSStub_7d69 {
  strings:
    $key_7d69 = { 29 01 [2] 5d 19 [2] 1a 1b [2] 5d 0a [2] 13 06 [2] 1f 0c [2] 08 07 [2] 13 49 [2] 2e }

  condition:
    any of them
}