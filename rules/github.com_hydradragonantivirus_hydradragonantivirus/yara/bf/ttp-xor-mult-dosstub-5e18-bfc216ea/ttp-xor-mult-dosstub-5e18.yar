rule TTP_XOR_MULT_DOSStub_5e18 {
  strings:
    $key_5e18 = { 0a 70 [2] 7e 68 [2] 39 6a [2] 7e 7b [2] 30 77 [2] 3c 7d [2] 2b 76 [2] 30 38 [2] 0d }

  condition:
    any of them
}