rule TTP_XOR_MULT_DOSStub_6159 {
  strings:
    $key_6159 = { 35 31 [2] 41 29 [2] 06 2b [2] 41 3a [2] 0f 36 [2] 03 3c [2] 14 37 [2] 0f 79 [2] 32 }

  condition:
    any of them
}