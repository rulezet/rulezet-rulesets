rule TTP_XOR_MULT_DOSStub_39e9 {
  strings:
    $key_39e9 = { 6d 81 [2] 19 99 [2] 5e 9b [2] 19 8a [2] 57 86 [2] 5b 8c [2] 4c 87 [2] 57 c9 [2] 6a }

  condition:
    any of them
}