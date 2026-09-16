rule TTP_XOR_MULT_DOSStub_0e05 {
  strings:
    $key_0e05 = { 5a 6d [2] 2e 75 [2] 69 77 [2] 2e 66 [2] 60 6a [2] 6c 60 [2] 7b 6b [2] 60 25 [2] 5d }

  condition:
    any of them
}