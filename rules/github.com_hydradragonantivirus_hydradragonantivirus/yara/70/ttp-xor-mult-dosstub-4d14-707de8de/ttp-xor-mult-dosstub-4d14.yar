rule TTP_XOR_MULT_DOSStub_4d14 {
  strings:
    $key_4d14 = { 19 7c [2] 6d 64 [2] 2a 66 [2] 6d 77 [2] 23 7b [2] 2f 71 [2] 38 7a [2] 23 34 [2] 1e }

  condition:
    any of them
}