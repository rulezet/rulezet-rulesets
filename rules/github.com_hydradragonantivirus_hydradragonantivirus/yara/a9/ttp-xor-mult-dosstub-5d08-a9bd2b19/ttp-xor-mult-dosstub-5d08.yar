rule TTP_XOR_MULT_DOSStub_5d08 {
  strings:
    $key_5d08 = { 09 60 [2] 7d 78 [2] 3a 7a [2] 7d 6b [2] 33 67 [2] 3f 6d [2] 28 66 [2] 33 28 [2] 0e }

  condition:
    any of them
}