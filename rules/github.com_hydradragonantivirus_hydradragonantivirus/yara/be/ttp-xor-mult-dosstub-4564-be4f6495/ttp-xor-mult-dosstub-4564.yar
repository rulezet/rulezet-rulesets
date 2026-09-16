rule TTP_XOR_MULT_DOSStub_4564 {
  strings:
    $key_4564 = { 11 0c [2] 65 14 [2] 22 16 [2] 65 07 [2] 2b 0b [2] 27 01 [2] 30 0a [2] 2b 44 [2] 16 }

  condition:
    any of them
}