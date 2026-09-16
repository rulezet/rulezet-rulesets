rule TTP_XOR_MULT_DOSStub_6838 {
  strings:
    $key_6838 = { 3c 50 [2] 48 48 [2] 0f 4a [2] 48 5b [2] 06 57 [2] 0a 5d [2] 1d 56 [2] 06 18 [2] 3b }

  condition:
    any of them
}