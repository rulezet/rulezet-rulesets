rule TTP_XOR_MULT_DOSStub_2654 {
  strings:
    $key_2654 = { 72 3c [2] 06 24 [2] 41 26 [2] 06 37 [2] 48 3b [2] 44 31 [2] 53 3a [2] 48 74 [2] 75 }

  condition:
    any of them
}