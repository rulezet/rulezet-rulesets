rule TTP_XOR_MULT_DOSStub_07f5 {
  strings:
    $key_07f5 = { 53 9d [2] 27 85 [2] 60 87 [2] 27 96 [2] 69 9a [2] 65 90 [2] 72 9b [2] 69 d5 [2] 54 }

  condition:
    any of them
}