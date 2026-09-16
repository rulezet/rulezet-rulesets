rule TTP_XOR_MULT_DOSStub_2238 {
  strings:
    $key_2238 = { 76 50 [2] 02 48 [2] 45 4a [2] 02 5b [2] 4c 57 [2] 40 5d [2] 57 56 [2] 4c 18 [2] 71 }

  condition:
    any of them
}