rule TTP_XOR_MULT_DOSStub_6145 {
  strings:
    $key_6145 = { 35 2d [2] 41 35 [2] 06 37 [2] 41 26 [2] 0f 2a [2] 03 20 [2] 14 2b [2] 0f 65 [2] 32 }

  condition:
    any of them
}