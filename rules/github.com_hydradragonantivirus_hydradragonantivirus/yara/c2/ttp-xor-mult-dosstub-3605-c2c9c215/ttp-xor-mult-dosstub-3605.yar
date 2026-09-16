rule TTP_XOR_MULT_DOSStub_3605 {
  strings:
    $key_3605 = { 62 6d [2] 16 75 [2] 51 77 [2] 16 66 [2] 58 6a [2] 54 60 [2] 43 6b [2] 58 25 [2] 65 }

  condition:
    any of them
}