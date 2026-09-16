rule TTP_XOR_MULT_DOSStub_5178 {
  strings:
    $key_5178 = { 05 10 [2] 71 08 [2] 36 0a [2] 71 1b [2] 3f 17 [2] 33 1d [2] 24 16 [2] 3f 58 [2] 02 }

  condition:
    any of them
}