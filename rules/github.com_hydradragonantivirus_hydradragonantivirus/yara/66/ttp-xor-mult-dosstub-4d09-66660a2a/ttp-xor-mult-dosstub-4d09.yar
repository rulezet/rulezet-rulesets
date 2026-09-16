rule TTP_XOR_MULT_DOSStub_4d09 {
  strings:
    $key_4d09 = { 19 61 [2] 6d 79 [2] 2a 7b [2] 6d 6a [2] 23 66 [2] 2f 6c [2] 38 67 [2] 23 29 [2] 1e }

  condition:
    any of them
}