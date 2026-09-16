rule TTP_XOR_MULT_DOSStub_08f5 {
  strings:
    $key_08f5 = { 5c 9d [2] 28 85 [2] 6f 87 [2] 28 96 [2] 66 9a [2] 6a 90 [2] 7d 9b [2] 66 d5 [2] 5b }

  condition:
    any of them
}