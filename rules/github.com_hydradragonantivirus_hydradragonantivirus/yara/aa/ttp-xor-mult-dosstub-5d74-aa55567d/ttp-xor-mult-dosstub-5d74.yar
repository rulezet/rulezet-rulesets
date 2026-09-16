rule TTP_XOR_MULT_DOSStub_5d74 {
  strings:
    $key_5d74 = { 09 1c [2] 7d 04 [2] 3a 06 [2] 7d 17 [2] 33 1b [2] 3f 11 [2] 28 1a [2] 33 54 [2] 0e }

  condition:
    any of them
}