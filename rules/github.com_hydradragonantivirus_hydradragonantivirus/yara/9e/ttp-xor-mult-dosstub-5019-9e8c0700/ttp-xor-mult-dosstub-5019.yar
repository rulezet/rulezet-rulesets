rule TTP_XOR_MULT_DOSStub_5019 {
  strings:
    $key_5019 = { 04 71 [2] 70 69 [2] 37 6b [2] 70 7a [2] 3e 76 [2] 32 7c [2] 25 77 [2] 3e 39 [2] 03 }

  condition:
    any of them
}