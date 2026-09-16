rule TTP_XOR_MULT_DOSStub_3654 {
  strings:
    $key_3654 = { 62 3c [2] 16 24 [2] 51 26 [2] 16 37 [2] 58 3b [2] 54 31 [2] 43 3a [2] 58 74 [2] 65 }

  condition:
    any of them
}