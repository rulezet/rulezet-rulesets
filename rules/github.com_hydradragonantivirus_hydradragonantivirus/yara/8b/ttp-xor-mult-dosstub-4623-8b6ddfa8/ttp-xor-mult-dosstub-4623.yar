rule TTP_XOR_MULT_DOSStub_4623 {
  strings:
    $key_4623 = { 12 4b [2] 66 53 [2] 21 51 [2] 66 40 [2] 28 4c [2] 24 46 [2] 33 4d [2] 28 03 [2] 15 }

  condition:
    any of them
}