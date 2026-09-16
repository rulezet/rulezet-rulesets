rule TTP_XOR_MULT_DOSStub_1804 {
  strings:
    $key_1804 = { 4c 6c [2] 38 74 [2] 7f 76 [2] 38 67 [2] 76 6b [2] 7a 61 [2] 6d 6a [2] 76 24 [2] 4b }

  condition:
    any of them
}