rule TTP_XOR_MULT_DOSStub_4604 {
  strings:
    $key_4604 = { 12 6c [2] 66 74 [2] 21 76 [2] 66 67 [2] 28 6b [2] 24 61 [2] 33 6a [2] 28 24 [2] 15 }

  condition:
    any of them
}