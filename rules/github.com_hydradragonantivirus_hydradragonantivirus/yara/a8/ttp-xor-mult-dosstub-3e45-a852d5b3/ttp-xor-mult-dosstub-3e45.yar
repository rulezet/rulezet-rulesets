rule TTP_XOR_MULT_DOSStub_3e45 {
  strings:
    $key_3e45 = { 6a 2d [2] 1e 35 [2] 59 37 [2] 1e 26 [2] 50 2a [2] 5c 20 [2] 4b 2b [2] 50 65 [2] 6d }

  condition:
    any of them
}