rule TTP_XOR_MULT_DOSStub_2274 {
  strings:
    $key_2274 = { 76 1c [2] 02 04 [2] 45 06 [2] 02 17 [2] 4c 1b [2] 40 11 [2] 57 1a [2] 4c 54 [2] 71 }

  condition:
    any of them
}