rule TTP_XOR_MULT_DOSStub_2249 {
  strings:
    $key_2249 = { 76 21 [2] 02 39 [2] 45 3b [2] 02 2a [2] 4c 26 [2] 40 2c [2] 57 27 [2] 4c 69 [2] 71 }

  condition:
    any of them
}