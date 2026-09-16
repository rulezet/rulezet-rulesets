rule TTP_XOR_MULT_DOSStub_62f5 {
  strings:
    $key_62f5 = { 36 9d [2] 42 85 [2] 05 87 [2] 42 96 [2] 0c 9a [2] 00 90 [2] 17 9b [2] 0c d5 [2] 31 }

  condition:
    any of them
}