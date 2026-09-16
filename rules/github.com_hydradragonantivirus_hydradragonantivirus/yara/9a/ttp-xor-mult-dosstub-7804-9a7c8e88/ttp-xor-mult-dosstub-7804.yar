rule TTP_XOR_MULT_DOSStub_7804 {
  strings:
    $key_7804 = { 2c 6c [2] 58 74 [2] 1f 76 [2] 58 67 [2] 16 6b [2] 1a 61 [2] 0d 6a [2] 16 24 [2] 2b }

  condition:
    any of them
}