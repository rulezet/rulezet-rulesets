rule TTP_XOR_MULT_DOSStub_0e14 {
  strings:
    $key_0e14 = { 5a 7c [2] 2e 64 [2] 69 66 [2] 2e 77 [2] 60 7b [2] 6c 71 [2] 7b 7a [2] 60 34 [2] 5d }

  condition:
    any of them
}