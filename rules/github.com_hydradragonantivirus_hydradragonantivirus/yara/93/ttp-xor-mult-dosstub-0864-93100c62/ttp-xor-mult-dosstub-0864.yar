rule TTP_XOR_MULT_DOSStub_0864 {
  strings:
    $key_0864 = { 5c 0c [2] 28 14 [2] 6f 16 [2] 28 07 [2] 66 0b [2] 6a 01 [2] 7d 0a [2] 66 44 [2] 5b }

  condition:
    any of them
}