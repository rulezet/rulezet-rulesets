rule TTP_XOR_MULT_DOSStub_0868 {
  strings:
    $key_0868 = { 5c 00 [2] 28 18 [2] 6f 1a [2] 28 0b [2] 66 07 [2] 6a 0d [2] 7d 06 [2] 66 48 [2] 5b }

  condition:
    any of them
}