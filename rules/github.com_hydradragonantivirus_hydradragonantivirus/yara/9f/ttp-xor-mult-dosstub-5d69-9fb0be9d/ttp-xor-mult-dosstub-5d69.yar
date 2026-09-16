rule TTP_XOR_MULT_DOSStub_5d69 {
  strings:
    $key_5d69 = { 09 01 [2] 7d 19 [2] 3a 1b [2] 7d 0a [2] 33 06 [2] 3f 0c [2] 28 07 [2] 33 49 [2] 0e }

  condition:
    any of them
}