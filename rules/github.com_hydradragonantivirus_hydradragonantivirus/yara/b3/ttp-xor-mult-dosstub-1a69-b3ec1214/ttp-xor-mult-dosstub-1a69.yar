rule TTP_XOR_MULT_DOSStub_1a69 {
  strings:
    $key_1a69 = { 4e 01 [2] 3a 19 [2] 7d 1b [2] 3a 0a [2] 74 06 [2] 78 0c [2] 6f 07 [2] 74 49 [2] 49 }

  condition:
    any of them
}