rule TTP_XOR_MULT_DOSStub_3154 {
  strings:
    $key_3154 = { 65 3c [2] 11 24 [2] 56 26 [2] 11 37 [2] 5f 3b [2] 53 31 [2] 44 3a [2] 5f 74 [2] 62 }

  condition:
    any of them
}