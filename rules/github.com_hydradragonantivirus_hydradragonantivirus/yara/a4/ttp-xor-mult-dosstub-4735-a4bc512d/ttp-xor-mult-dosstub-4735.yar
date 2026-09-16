rule TTP_XOR_MULT_DOSStub_4735 {
  strings:
    $key_4735 = { 13 5d [2] 67 45 [2] 20 47 [2] 67 56 [2] 29 5a [2] 25 50 [2] 32 5b [2] 29 15 [2] 14 }

  condition:
    any of them
}