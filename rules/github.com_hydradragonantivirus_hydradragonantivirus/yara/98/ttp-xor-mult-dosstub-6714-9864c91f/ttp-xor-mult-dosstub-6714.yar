rule TTP_XOR_MULT_DOSStub_6714 {
  strings:
    $key_6714 = { 33 7c [2] 47 64 [2] 00 66 [2] 47 77 [2] 09 7b [2] 05 71 [2] 12 7a [2] 09 34 [2] 34 }

  condition:
    any of them
}