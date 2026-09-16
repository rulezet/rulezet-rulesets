rule TTP_XOR_MULT_DOSStub_0878 {
  strings:
    $key_0878 = { 5c 10 [2] 28 08 [2] 6f 0a [2] 28 1b [2] 66 17 [2] 6a 1d [2] 7d 16 [2] 66 58 [2] 5b }

  condition:
    any of them
}