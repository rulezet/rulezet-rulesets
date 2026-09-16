rule TTP_XOR_MULT_DOSStub_6314 {
  strings:
    $key_6314 = { 37 7c [2] 43 64 [2] 04 66 [2] 43 77 [2] 0d 7b [2] 01 71 [2] 16 7a [2] 0d 34 [2] 30 }

  condition:
    any of them
}