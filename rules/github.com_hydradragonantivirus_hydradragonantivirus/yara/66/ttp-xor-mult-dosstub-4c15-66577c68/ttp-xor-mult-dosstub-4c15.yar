rule TTP_XOR_MULT_DOSStub_4c15 {
  strings:
    $key_4c15 = { 18 7d [2] 6c 65 [2] 2b 67 [2] 6c 76 [2] 22 7a [2] 2e 70 [2] 39 7b [2] 22 35 [2] 1f }

  condition:
    any of them
}