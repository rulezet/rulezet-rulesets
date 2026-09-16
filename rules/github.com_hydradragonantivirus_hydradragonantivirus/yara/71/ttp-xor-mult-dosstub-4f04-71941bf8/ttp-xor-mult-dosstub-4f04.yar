rule TTP_XOR_MULT_DOSStub_4f04 {
  strings:
    $key_4f04 = { 1b 6c [2] 6f 74 [2] 28 76 [2] 6f 67 [2] 21 6b [2] 2d 61 [2] 3a 6a [2] 21 24 [2] 1c }

  condition:
    any of them
}