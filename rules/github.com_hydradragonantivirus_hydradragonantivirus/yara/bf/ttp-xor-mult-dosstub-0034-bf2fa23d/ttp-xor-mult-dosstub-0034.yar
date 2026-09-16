rule TTP_XOR_MULT_DOSStub_0034 {
  strings:
    $key_0034 = { 54 5c [2] 20 44 [2] 67 46 [2] 20 57 [2] 6e 5b [2] 62 51 [2] 75 5a [2] 6e 14 [2] 53 }

  condition:
    any of them
}