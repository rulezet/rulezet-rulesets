rule TTP_XOR_MULT_DOSStub_4669 {
  strings:
    $key_4669 = { 12 01 [2] 66 19 [2] 21 1b [2] 66 0a [2] 28 06 [2] 24 0c [2] 33 07 [2] 28 49 [2] 15 }

  condition:
    any of them
}