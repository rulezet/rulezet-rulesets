rule TTP_XOR_MULT_DOSStub_6105 {
  strings:
    $key_6105 = { 35 6d [2] 41 75 [2] 06 77 [2] 41 66 [2] 0f 6a [2] 03 60 [2] 14 6b [2] 0f 25 [2] 32 }

  condition:
    any of them
}