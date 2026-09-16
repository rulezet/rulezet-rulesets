rule TTP_XOR_MULT_DOSStub_4be4 {
  strings:
    $key_4be4 = { 1f 8c [2] 6b 94 [2] 2c 96 [2] 6b 87 [2] 25 8b [2] 29 81 [2] 3e 8a [2] 25 c4 [2] 18 }

  condition:
    any of them
}