rule TTP_XOR_MULT_DOSStub_0e78 {
  strings:
    $key_0e78 = { 5a 10 [2] 2e 08 [2] 69 0a [2] 2e 1b [2] 60 17 [2] 6c 1d [2] 7b 16 [2] 60 58 [2] 5d }

  condition:
    any of them
}