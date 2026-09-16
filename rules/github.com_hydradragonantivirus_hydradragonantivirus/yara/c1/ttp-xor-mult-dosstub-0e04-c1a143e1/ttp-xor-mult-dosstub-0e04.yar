rule TTP_XOR_MULT_DOSStub_0e04 {
  strings:
    $key_0e04 = { 5a 6c [2] 2e 74 [2] 69 76 [2] 2e 67 [2] 60 6b [2] 6c 61 [2] 7b 6a [2] 60 24 [2] 5d }

  condition:
    any of them
}