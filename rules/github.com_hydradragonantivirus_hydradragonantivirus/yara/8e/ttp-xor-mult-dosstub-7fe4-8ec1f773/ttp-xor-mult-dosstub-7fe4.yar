rule TTP_XOR_MULT_DOSStub_7fe4 {
  strings:
    $key_7fe4 = { 2b 8c [2] 5f 94 [2] 18 96 [2] 5f 87 [2] 11 8b [2] 1d 81 [2] 0a 8a [2] 11 c4 [2] 2c }

  condition:
    any of them
}