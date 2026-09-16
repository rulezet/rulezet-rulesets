rule TTP_XOR_MULT_DOSStub_4624 {
  strings:
    $key_4624 = { 12 4c [2] 66 54 [2] 21 56 [2] 66 47 [2] 28 4b [2] 24 41 [2] 33 4a [2] 28 04 [2] 15 }

  condition:
    any of them
}