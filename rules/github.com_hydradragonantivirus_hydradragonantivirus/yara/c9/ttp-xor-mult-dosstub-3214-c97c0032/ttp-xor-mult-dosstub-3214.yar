rule TTP_XOR_MULT_DOSStub_3214 {
  strings:
    $key_3214 = { 66 7c [2] 12 64 [2] 55 66 [2] 12 77 [2] 5c 7b [2] 50 71 [2] 47 7a [2] 5c 34 [2] 61 }

  condition:
    any of them
}