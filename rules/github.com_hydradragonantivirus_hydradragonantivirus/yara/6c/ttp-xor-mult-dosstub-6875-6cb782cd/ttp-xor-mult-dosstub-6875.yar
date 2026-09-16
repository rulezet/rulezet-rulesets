rule TTP_XOR_MULT_DOSStub_6875 {
  strings:
    $key_6875 = { 3c 1d [2] 48 05 [2] 0f 07 [2] 48 16 [2] 06 1a [2] 0a 10 [2] 1d 1b [2] 06 55 [2] 3b }

  condition:
    any of them
}