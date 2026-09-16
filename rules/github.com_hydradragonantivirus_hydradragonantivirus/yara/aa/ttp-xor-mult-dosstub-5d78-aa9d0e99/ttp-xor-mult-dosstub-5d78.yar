rule TTP_XOR_MULT_DOSStub_5d78 {
  strings:
    $key_5d78 = { 09 10 [2] 7d 08 [2] 3a 0a [2] 7d 1b [2] 33 17 [2] 3f 1d [2] 28 16 [2] 33 58 [2] 0e }

  condition:
    any of them
}