rule TTP_XOR_MULT_DOSStub_7c35 {
  strings:
    $key_7c35 = { 28 5d [2] 5c 45 [2] 1b 47 [2] 5c 56 [2] 12 5a [2] 1e 50 [2] 09 5b [2] 12 15 [2] 2f }

  condition:
    any of them
}