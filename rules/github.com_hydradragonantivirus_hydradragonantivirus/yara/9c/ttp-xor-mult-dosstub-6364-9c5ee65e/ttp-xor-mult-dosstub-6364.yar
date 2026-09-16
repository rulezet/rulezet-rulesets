rule TTP_XOR_MULT_DOSStub_6364 {
  strings:
    $key_6364 = { 37 0c [2] 43 14 [2] 04 16 [2] 43 07 [2] 0d 0b [2] 01 01 [2] 16 0a [2] 0d 44 [2] 30 }

  condition:
    any of them
}