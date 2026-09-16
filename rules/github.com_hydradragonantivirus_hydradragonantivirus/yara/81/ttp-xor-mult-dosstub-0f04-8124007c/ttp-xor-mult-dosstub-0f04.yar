rule TTP_XOR_MULT_DOSStub_0f04 {
  strings:
    $key_0f04 = { 5b 6c [2] 2f 74 [2] 68 76 [2] 2f 67 [2] 61 6b [2] 6d 61 [2] 7a 6a [2] 61 24 [2] 5c }

  condition:
    any of them
}