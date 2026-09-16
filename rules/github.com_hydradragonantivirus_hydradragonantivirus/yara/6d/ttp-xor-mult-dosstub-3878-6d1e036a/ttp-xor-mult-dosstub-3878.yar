rule TTP_XOR_MULT_DOSStub_3878 {
  strings:
    $key_3878 = { 6c 10 [2] 18 08 [2] 5f 0a [2] 18 1b [2] 56 17 [2] 5a 1d [2] 4d 16 [2] 56 58 [2] 6b }

  condition:
    any of them
}