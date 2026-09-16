rule TTP_XOR_MULT_DOSStub_4569 {
  strings:
    $key_4569 = { 11 01 [2] 65 19 [2] 22 1b [2] 65 0a [2] 2b 06 [2] 27 0c [2] 30 07 [2] 2b 49 [2] 16 }

  condition:
    any of them
}