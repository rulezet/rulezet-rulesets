rule TTP_XOR_MULT_DOSStub_0e08 {
  strings:
    $key_0e08 = { 5a 60 [2] 2e 78 [2] 69 7a [2] 2e 6b [2] 60 67 [2] 6c 6d [2] 7b 66 [2] 60 28 [2] 5d }

  condition:
    any of them
}