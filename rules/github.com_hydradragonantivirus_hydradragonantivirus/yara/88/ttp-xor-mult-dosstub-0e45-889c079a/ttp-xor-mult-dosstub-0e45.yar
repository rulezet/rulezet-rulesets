rule TTP_XOR_MULT_DOSStub_0e45 {
  strings:
    $key_0e45 = { 5a 2d [2] 2e 35 [2] 69 37 [2] 2e 26 [2] 60 2a [2] 6c 20 [2] 7b 2b [2] 60 65 [2] 5d }

  condition:
    any of them
}