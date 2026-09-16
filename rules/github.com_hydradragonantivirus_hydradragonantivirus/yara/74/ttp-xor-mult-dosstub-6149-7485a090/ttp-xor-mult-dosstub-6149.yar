rule TTP_XOR_MULT_DOSStub_6149 {
  strings:
    $key_6149 = { 35 21 [2] 41 39 [2] 06 3b [2] 41 2a [2] 0f 26 [2] 03 2c [2] 14 27 [2] 0f 69 [2] 32 }

  condition:
    any of them
}