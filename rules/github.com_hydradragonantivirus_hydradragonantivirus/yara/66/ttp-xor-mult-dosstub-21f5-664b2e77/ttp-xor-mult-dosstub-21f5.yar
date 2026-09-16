rule TTP_XOR_MULT_DOSStub_21f5 {
  strings:
    $key_21f5 = { 75 9d [2] 01 85 [2] 46 87 [2] 01 96 [2] 4f 9a [2] 43 90 [2] 54 9b [2] 4f d5 [2] 72 }

  condition:
    any of them
}