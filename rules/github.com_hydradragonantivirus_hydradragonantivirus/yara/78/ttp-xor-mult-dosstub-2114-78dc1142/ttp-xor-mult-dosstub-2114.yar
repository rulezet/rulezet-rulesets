rule TTP_XOR_MULT_DOSStub_2114 {
  strings:
    $key_2114 = { 75 7c [2] 01 64 [2] 46 66 [2] 01 77 [2] 4f 7b [2] 43 71 [2] 54 7a [2] 4f 34 [2] 72 }

  condition:
    any of them
}