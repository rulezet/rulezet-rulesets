rule TTP_XOR_MULT_DOSStub_4738 {
  strings:
    $key_4738 = { 13 50 [2] 67 48 [2] 20 4a [2] 67 5b [2] 29 57 [2] 25 5d [2] 32 56 [2] 29 18 [2] 14 }

  condition:
    any of them
}