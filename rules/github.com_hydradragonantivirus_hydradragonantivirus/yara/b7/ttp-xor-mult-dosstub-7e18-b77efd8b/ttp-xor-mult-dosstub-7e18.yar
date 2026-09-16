rule TTP_XOR_MULT_DOSStub_7e18 {
  strings:
    $key_7e18 = { 2a 70 [2] 5e 68 [2] 19 6a [2] 5e 7b [2] 10 77 [2] 1c 7d [2] 0b 76 [2] 10 38 [2] 2d }

  condition:
    any of them
}