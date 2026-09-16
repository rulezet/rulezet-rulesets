rule TTP_XOR_MULT_DOSStub_6174 {
  strings:
    $key_6174 = { 35 1c [2] 41 04 [2] 06 06 [2] 41 17 [2] 0f 1b [2] 03 11 [2] 14 1a [2] 0f 54 [2] 32 }

  condition:
    any of them
}