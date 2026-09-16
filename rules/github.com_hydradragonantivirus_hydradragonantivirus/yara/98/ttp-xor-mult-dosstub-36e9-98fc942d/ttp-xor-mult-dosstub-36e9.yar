rule TTP_XOR_MULT_DOSStub_36e9 {
  strings:
    $key_36e9 = { 62 81 [2] 16 99 [2] 51 9b [2] 16 8a [2] 58 86 [2] 54 8c [2] 43 87 [2] 58 c9 [2] 65 }

  condition:
    any of them
}