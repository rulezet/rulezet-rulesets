rule TTP_XOR_MULT_DOSStub_4c05 {
  strings:
    $key_4c05 = { 18 6d [2] 6c 75 [2] 2b 77 [2] 6c 66 [2] 22 6a [2] 2e 60 [2] 39 6b [2] 22 25 [2] 1f }

  condition:
    any of them
}