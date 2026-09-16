rule TTP_XOR_MULT_DOSStub_0e02 {
  strings:
    $key_0e02 = { 5a 6a [2] 2e 72 [2] 69 70 [2] 2e 61 [2] 60 6d [2] 6c 67 [2] 7b 6c [2] 60 22 [2] 5d }

  condition:
    any of them
}