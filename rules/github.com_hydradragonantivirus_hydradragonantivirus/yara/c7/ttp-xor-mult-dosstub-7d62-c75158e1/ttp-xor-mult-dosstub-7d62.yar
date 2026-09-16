rule TTP_XOR_MULT_DOSStub_7d62 {
  strings:
    $key_7d62 = { 29 0a [2] 5d 12 [2] 1a 10 [2] 5d 01 [2] 13 0d [2] 1f 07 [2] 08 0c [2] 13 42 [2] 2e }

  condition:
    any of them
}