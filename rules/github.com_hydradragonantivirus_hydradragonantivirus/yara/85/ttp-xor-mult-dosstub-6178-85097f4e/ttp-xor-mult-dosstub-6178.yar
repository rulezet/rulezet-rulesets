rule TTP_XOR_MULT_DOSStub_6178 {
  strings:
    $key_6178 = { 35 10 [2] 41 08 [2] 06 0a [2] 41 1b [2] 0f 17 [2] 03 1d [2] 14 16 [2] 0f 58 [2] 32 }

  condition:
    any of them
}