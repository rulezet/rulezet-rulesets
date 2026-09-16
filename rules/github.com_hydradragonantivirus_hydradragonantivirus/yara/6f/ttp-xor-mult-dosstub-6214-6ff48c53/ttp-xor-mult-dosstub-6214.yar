rule TTP_XOR_MULT_DOSStub_6214 {
  strings:
    $key_6214 = { 36 7c [2] 42 64 [2] 05 66 [2] 42 77 [2] 0c 7b [2] 00 71 [2] 17 7a [2] 0c 34 [2] 31 }

  condition:
    any of them
}