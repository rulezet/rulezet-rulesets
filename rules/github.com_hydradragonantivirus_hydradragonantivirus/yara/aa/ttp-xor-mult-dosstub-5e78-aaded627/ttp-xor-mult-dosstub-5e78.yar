rule TTP_XOR_MULT_DOSStub_5e78 {
  strings:
    $key_5e78 = { 0a 10 [2] 7e 08 [2] 39 0a [2] 7e 1b [2] 30 17 [2] 3c 1d [2] 2b 16 [2] 30 58 [2] 0d }

  condition:
    any of them
}