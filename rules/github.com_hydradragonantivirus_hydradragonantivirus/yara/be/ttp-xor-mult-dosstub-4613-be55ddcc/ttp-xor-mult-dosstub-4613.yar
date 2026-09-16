rule TTP_XOR_MULT_DOSStub_4613 {
  strings:
    $key_4613 = { 12 7b [2] 66 63 [2] 21 61 [2] 66 70 [2] 28 7c [2] 24 76 [2] 33 7d [2] 28 33 [2] 15 }

  condition:
    any of them
}