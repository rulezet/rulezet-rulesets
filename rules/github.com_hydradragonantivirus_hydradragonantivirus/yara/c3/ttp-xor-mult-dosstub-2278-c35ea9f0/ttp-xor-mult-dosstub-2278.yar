rule TTP_XOR_MULT_DOSStub_2278 {
  strings:
    $key_2278 = { 76 10 [2] 02 08 [2] 45 0a [2] 02 1b [2] 4c 17 [2] 40 1d [2] 57 16 [2] 4c 58 [2] 71 }

  condition:
    any of them
}