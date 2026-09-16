rule TTP_XOR_MULT_DOSStub_1439 {
  strings:
    $key_1439 = { 40 51 [2] 34 49 [2] 73 4b [2] 34 5a [2] 7a 56 [2] 76 5c [2] 61 57 [2] 7a 19 [2] 47 }

  condition:
    any of them
}