rule TTP_XOR_MULT_DOSStub_4369 {
  strings:
    $key_4369 = { 17 01 [2] 63 19 [2] 24 1b [2] 63 0a [2] 2d 06 [2] 21 0c [2] 36 07 [2] 2d 49 [2] 10 }

  condition:
    any of them
}