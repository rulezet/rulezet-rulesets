rule TTP_XOR_MULT_DOSStub_7a19 {
  strings:
    $key_7a19 = { 2e 71 [2] 5a 69 [2] 1d 6b [2] 5a 7a [2] 14 76 [2] 18 7c [2] 0f 77 [2] 14 39 [2] 29 }

  condition:
    any of them
}