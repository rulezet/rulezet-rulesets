rule TTP_XOR_MULT_DOSStub_6378 {
  strings:
    $key_6378 = { 37 10 [2] 43 08 [2] 04 0a [2] 43 1b [2] 0d 17 [2] 01 1d [2] 16 16 [2] 0d 58 [2] 30 }

  condition:
    any of them
}