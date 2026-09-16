rule TTP_XOR_MULT_DOSStub_1435 {
  strings:
    $key_1435 = { 40 5d [2] 34 45 [2] 73 47 [2] 34 56 [2] 7a 5a [2] 76 50 [2] 61 5b [2] 7a 15 [2] 47 }

  condition:
    any of them
}