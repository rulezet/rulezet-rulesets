rule TTP_XOR_MULT_DOSStub_5214 {
  strings:
    $key_5214 = { 06 7c [2] 72 64 [2] 35 66 [2] 72 77 [2] 3c 7b [2] 30 71 [2] 27 7a [2] 3c 34 [2] 01 }

  condition:
    any of them
}