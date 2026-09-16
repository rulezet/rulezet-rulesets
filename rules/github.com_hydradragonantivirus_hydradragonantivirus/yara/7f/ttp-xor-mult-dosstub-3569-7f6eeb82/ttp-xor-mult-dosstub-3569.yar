rule TTP_XOR_MULT_DOSStub_3569 {
  strings:
    $key_3569 = { 61 01 [2] 15 19 [2] 52 1b [2] 15 0a [2] 5b 06 [2] 57 0c [2] 40 07 [2] 5b 49 [2] 66 }

  condition:
    any of them
}