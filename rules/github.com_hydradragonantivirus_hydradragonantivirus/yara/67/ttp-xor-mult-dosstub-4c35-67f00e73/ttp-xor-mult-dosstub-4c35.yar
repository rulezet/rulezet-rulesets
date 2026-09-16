rule TTP_XOR_MULT_DOSStub_4c35 {
  strings:
    $key_4c35 = { 18 5d [2] 6c 45 [2] 2b 47 [2] 6c 56 [2] 22 5a [2] 2e 50 [2] 39 5b [2] 22 15 [2] 1f }

  condition:
    any of them
}