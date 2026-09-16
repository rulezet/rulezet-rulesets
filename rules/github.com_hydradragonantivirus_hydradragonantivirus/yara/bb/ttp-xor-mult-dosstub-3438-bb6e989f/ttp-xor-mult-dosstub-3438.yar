rule TTP_XOR_MULT_DOSStub_3438 {
  strings:
    $key_3438 = { 60 50 [2] 14 48 [2] 53 4a [2] 14 5b [2] 5a 57 [2] 56 5d [2] 41 56 [2] 5a 18 [2] 67 }

  condition:
    any of them
}