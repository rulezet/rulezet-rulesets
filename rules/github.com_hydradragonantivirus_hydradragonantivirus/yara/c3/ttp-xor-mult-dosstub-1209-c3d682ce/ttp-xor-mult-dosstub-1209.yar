rule TTP_XOR_MULT_DOSStub_1209 {
  strings:
    $key_1209 = { 46 61 [2] 32 79 [2] 75 7b [2] 32 6a [2] 7c 66 [2] 70 6c [2] 67 67 [2] 7c 29 [2] 41 }

  condition:
    any of them
}