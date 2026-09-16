rule TTP_XOR_MULT_DOSStub_0e49 {
  strings:
    $key_0e49 = { 5a 21 [2] 2e 39 [2] 69 3b [2] 2e 2a [2] 60 26 [2] 6c 2c [2] 7b 27 [2] 60 69 [2] 5d }

  condition:
    any of them
}