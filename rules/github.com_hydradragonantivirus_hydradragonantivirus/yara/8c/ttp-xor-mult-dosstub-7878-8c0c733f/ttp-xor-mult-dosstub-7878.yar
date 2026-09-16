rule TTP_XOR_MULT_DOSStub_7878 {
  strings:
    $key_7878 = { 2c 10 [2] 58 08 [2] 1f 0a [2] 58 1b [2] 16 17 [2] 1a 1d [2] 0d 16 [2] 16 58 [2] 2b }

  condition:
    any of them
}