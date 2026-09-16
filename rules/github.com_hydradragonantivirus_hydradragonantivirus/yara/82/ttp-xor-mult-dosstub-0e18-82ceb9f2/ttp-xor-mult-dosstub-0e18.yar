rule TTP_XOR_MULT_DOSStub_0e18 {
  strings:
    $key_0e18 = { 5a 70 [2] 2e 68 [2] 69 6a [2] 2e 7b [2] 60 77 [2] 6c 7d [2] 7b 76 [2] 60 38 [2] 5d }

  condition:
    any of them
}