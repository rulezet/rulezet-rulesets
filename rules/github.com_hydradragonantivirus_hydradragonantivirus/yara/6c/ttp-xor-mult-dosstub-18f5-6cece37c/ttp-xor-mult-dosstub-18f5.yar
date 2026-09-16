rule TTP_XOR_MULT_DOSStub_18f5 {
  strings:
    $key_18f5 = { 4c 9d [2] 38 85 [2] 7f 87 [2] 38 96 [2] 76 9a [2] 7a 90 [2] 6d 9b [2] 76 d5 [2] 4b }

  condition:
    any of them
}