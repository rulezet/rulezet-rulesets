rule TTP_XOR_MULT_DOSStub_7623 {
  strings:
    $key_7623 = { 22 4b [2] 56 53 [2] 11 51 [2] 56 40 [2] 18 4c [2] 14 46 [2] 03 4d [2] 18 03 [2] 25 }

  condition:
    any of them
}