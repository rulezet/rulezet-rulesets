rule TTP_XOR_MULT_DOSStub_7214 {
  strings:
    $key_7214 = { 26 7c [2] 52 64 [2] 15 66 [2] 52 77 [2] 1c 7b [2] 10 71 [2] 07 7a [2] 1c 34 [2] 21 }

  condition:
    any of them
}