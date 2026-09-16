rule TTP_XOR_MULT_DOSStub_0259 {
  strings:
    $key_0259 = { 56 31 [2] 22 29 [2] 65 2b [2] 22 3a [2] 6c 36 [2] 60 3c [2] 77 37 [2] 6c 79 [2] 51 }

  condition:
    any of them
}