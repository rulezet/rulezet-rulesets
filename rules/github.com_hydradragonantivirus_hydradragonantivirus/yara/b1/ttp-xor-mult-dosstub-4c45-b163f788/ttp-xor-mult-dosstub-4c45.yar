rule TTP_XOR_MULT_DOSStub_4c45 {
  strings:
    $key_4c45 = { 18 2d [2] 6c 35 [2] 2b 37 [2] 6c 26 [2] 22 2a [2] 2e 20 [2] 39 2b [2] 22 65 [2] 1f }

  condition:
    any of them
}