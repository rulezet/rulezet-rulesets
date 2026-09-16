rule TTP_XOR_MULT_DOSStub_4609 {
  strings:
    $key_4609 = { 12 61 [2] 66 79 [2] 21 7b [2] 66 6a [2] 28 66 [2] 24 6c [2] 33 67 [2] 28 29 [2] 15 }

  condition:
    any of them
}