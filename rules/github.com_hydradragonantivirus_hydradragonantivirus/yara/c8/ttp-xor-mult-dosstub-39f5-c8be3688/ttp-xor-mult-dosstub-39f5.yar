rule TTP_XOR_MULT_DOSStub_39f5 {
  strings:
    $key_39f5 = { 6d 9d [2] 19 85 [2] 5e 87 [2] 19 96 [2] 57 9a [2] 5b 90 [2] 4c 9b [2] 57 d5 [2] 6a }

  condition:
    any of them
}