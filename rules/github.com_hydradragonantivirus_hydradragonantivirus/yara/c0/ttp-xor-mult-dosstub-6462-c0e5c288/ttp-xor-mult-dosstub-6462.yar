rule TTP_XOR_MULT_DOSStub_6462 {
  strings:
    $key_6462 = { 30 0a [2] 44 12 [2] 03 10 [2] 44 01 [2] 0a 0d [2] 06 07 [2] 11 0c [2] 0a 42 [2] 37 }

  condition:
    any of them
}