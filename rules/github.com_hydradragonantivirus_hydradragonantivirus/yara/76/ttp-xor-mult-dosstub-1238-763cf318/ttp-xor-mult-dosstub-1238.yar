rule TTP_XOR_MULT_DOSStub_1238 {
  strings:
    $key_1238 = { 46 50 [2] 32 48 [2] 75 4a [2] 32 5b [2] 7c 57 [2] 70 5d [2] 67 56 [2] 7c 18 [2] 41 }

  condition:
    any of them
}