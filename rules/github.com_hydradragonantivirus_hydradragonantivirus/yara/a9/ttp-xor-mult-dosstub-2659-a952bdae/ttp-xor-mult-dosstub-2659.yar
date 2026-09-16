rule TTP_XOR_MULT_DOSStub_2659 {
  strings:
    $key_2659 = { 72 31 [2] 06 29 [2] 41 2b [2] 06 3a [2] 48 36 [2] 44 3c [2] 53 37 [2] 48 79 [2] 75 }

  condition:
    any of them
}