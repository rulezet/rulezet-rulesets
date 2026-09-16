rule TTP_XOR_MULT_DOSStub_0714 {
  strings:
    $key_0714 = { 53 7c [2] 27 64 [2] 60 66 [2] 27 77 [2] 69 7b [2] 65 71 [2] 72 7a [2] 69 34 [2] 54 }

  condition:
    any of them
}