rule TTP_XOR_MULT_DOSStub_6d04 {
  strings:
    $key_6d04 = { 39 6c [2] 4d 74 [2] 0a 76 [2] 4d 67 [2] 03 6b [2] 0f 61 [2] 18 6a [2] 03 24 [2] 3e }

  condition:
    any of them
}