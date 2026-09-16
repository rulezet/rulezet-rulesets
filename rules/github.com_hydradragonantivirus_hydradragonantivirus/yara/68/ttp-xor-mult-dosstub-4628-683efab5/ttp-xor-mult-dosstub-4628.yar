rule TTP_XOR_MULT_DOSStub_4628 {
  strings:
    $key_4628 = { 12 40 [2] 66 58 [2] 21 5a [2] 66 4b [2] 28 47 [2] 24 4d [2] 33 46 [2] 28 08 [2] 15 }

  condition:
    any of them
}