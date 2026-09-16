rule TTP_XOR_MULT_DOSStub_5e45 {
  strings:
    $key_5e45 = { 0a 2d [2] 7e 35 [2] 39 37 [2] 7e 26 [2] 30 2a [2] 3c 20 [2] 2b 2b [2] 30 65 [2] 0d }

  condition:
    any of them
}