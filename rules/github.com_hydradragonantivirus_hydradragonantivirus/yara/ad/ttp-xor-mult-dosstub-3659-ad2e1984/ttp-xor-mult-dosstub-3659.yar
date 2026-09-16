rule TTP_XOR_MULT_DOSStub_3659 {
  strings:
    $key_3659 = { 62 31 [2] 16 29 [2] 51 2b [2] 16 3a [2] 58 36 [2] 54 3c [2] 43 37 [2] 58 79 [2] 65 }

  condition:
    any of them
}