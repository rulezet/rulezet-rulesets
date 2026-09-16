rule TTP_XOR_MULT_DOSStub_2234 {
  strings:
    $key_2234 = { 76 5c [2] 02 44 [2] 45 46 [2] 02 57 [2] 4c 5b [2] 40 51 [2] 57 5a [2] 4c 14 [2] 71 }

  condition:
    any of them
}