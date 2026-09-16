rule TTP_XOR_MULT_DOSStub_3508 {
  strings:
    $key_3508 = { 61 60 [2] 15 78 [2] 52 7a [2] 15 6b [2] 5b 67 [2] 57 6d [2] 40 66 [2] 5b 28 [2] 66 }

  condition:
    any of them
}