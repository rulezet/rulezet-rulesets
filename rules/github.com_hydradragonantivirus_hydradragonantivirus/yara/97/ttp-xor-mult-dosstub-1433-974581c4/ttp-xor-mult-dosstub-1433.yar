rule TTP_XOR_MULT_DOSStub_1433 {
  strings:
    $key_1433 = { 40 5b [2] 34 43 [2] 73 41 [2] 34 50 [2] 7a 5c [2] 76 56 [2] 61 5d [2] 7a 13 [2] 47 }

  condition:
    any of them
}