rule TTP_XOR_MULT_DOSStub_0e44 {
  strings:
    $key_0e44 = { 5a 2c [2] 2e 34 [2] 69 36 [2] 2e 27 [2] 60 2b [2] 6c 21 [2] 7b 2a [2] 60 64 [2] 5d }

  condition:
    any of them
}