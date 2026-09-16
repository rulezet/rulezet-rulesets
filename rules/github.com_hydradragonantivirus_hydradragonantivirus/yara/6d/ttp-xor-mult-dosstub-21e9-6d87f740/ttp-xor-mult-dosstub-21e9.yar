rule TTP_XOR_MULT_DOSStub_21e9 {
  strings:
    $key_21e9 = { 75 81 [2] 01 99 [2] 46 9b [2] 01 8a [2] 4f 86 [2] 43 8c [2] 54 87 [2] 4f c9 [2] 72 }

  condition:
    any of them
}