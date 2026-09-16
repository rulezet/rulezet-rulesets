rule TTP_XOR_MULT_DOSStub_5d62 {
  strings:
    $key_5d62 = { 09 0a [2] 7d 12 [2] 3a 10 [2] 7d 01 [2] 33 0d [2] 3f 07 [2] 28 0c [2] 33 42 [2] 0e }

  condition:
    any of them
}