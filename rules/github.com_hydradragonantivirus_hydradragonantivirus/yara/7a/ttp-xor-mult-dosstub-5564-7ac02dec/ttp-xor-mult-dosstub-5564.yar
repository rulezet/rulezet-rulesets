rule TTP_XOR_MULT_DOSStub_5564 {
  strings:
    $key_5564 = { 01 0c [2] 75 14 [2] 32 16 [2] 75 07 [2] 3b 0b [2] 37 01 [2] 20 0a [2] 3b 44 [2] 06 }

  condition:
    any of them
}