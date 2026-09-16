rule TTP_XOR_MULT_DOSStub_6862 {
  strings:
    $key_6862 = { 3c 0a [2] 48 12 [2] 0f 10 [2] 48 01 [2] 06 0d [2] 0a 07 [2] 1d 0c [2] 06 42 [2] 3b }

  condition:
    any of them
}