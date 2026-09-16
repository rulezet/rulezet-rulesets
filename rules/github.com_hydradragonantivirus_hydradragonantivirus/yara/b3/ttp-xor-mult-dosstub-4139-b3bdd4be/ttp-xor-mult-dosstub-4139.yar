rule TTP_XOR_MULT_DOSStub_4139 {
  strings:
    $key_4139 = { 15 51 [2] 61 49 [2] 26 4b [2] 61 5a [2] 2f 56 [2] 23 5c [2] 34 57 [2] 2f 19 [2] 12 }

  condition:
    any of them
}