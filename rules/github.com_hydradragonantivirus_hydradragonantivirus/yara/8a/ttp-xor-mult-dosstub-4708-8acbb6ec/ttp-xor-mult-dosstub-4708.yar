rule TTP_XOR_MULT_DOSStub_4708 {
  strings:
    $key_4708 = { 13 60 [2] 67 78 [2] 20 7a [2] 67 6b [2] 29 67 [2] 25 6d [2] 32 66 [2] 29 28 [2] 14 }

  condition:
    any of them
}