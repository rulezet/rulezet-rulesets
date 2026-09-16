rule TTP_XOR_MULT_DOSStub_6818 {
  strings:
    $key_6818 = { 3c 70 [2] 48 68 [2] 0f 6a [2] 48 7b [2] 06 77 [2] 0a 7d [2] 1d 76 [2] 06 38 [2] 3b }

  condition:
    any of them
}