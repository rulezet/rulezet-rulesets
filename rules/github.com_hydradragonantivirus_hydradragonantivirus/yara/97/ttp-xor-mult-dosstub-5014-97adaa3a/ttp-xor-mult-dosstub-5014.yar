rule TTP_XOR_MULT_DOSStub_5014 {
  strings:
    $key_5014 = { 04 7c [2] 70 64 [2] 37 66 [2] 70 77 [2] 3e 7b [2] 32 71 [2] 25 7a [2] 3e 34 [2] 03 }

  condition:
    any of them
}