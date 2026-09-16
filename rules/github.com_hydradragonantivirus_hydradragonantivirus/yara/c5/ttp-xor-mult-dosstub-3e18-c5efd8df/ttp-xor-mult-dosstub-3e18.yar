rule TTP_XOR_MULT_DOSStub_3e18 {
  strings:
    $key_3e18 = { 6a 70 [2] 1e 68 [2] 59 6a [2] 1e 7b [2] 50 77 [2] 5c 7d [2] 4b 76 [2] 50 38 [2] 6d }

  condition:
    any of them
}