rule TTP_XOR_MULT_DOSStub_1878 {
  strings:
    $key_1878 = { 4c 10 [2] 38 08 [2] 7f 0a [2] 38 1b [2] 76 17 [2] 7a 1d [2] 6d 16 [2] 76 58 [2] 4b }

  condition:
    any of them
}