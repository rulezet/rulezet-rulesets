rule TTP_XOR_MULT_DOSStub_4d04 {
  strings:
    $key_4d04 = { 19 6c [2] 6d 74 [2] 2a 76 [2] 6d 67 [2] 23 6b [2] 2f 61 [2] 38 6a [2] 23 24 [2] 1e }

  condition:
    any of them
}