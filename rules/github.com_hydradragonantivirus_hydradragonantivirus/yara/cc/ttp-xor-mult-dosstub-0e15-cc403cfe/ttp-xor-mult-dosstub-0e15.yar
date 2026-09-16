rule TTP_XOR_MULT_DOSStub_0e15 {
  strings:
    $key_0e15 = { 5a 7d [2] 2e 65 [2] 69 67 [2] 2e 76 [2] 60 7a [2] 6c 70 [2] 7b 7b [2] 60 35 [2] 5d }

  condition:
    any of them
}