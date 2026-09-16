rule TTP_XOR_MULT_DOSStub_3435 {
  strings:
    $key_3435 = { 60 5d [2] 14 45 [2] 53 47 [2] 14 56 [2] 5a 5a [2] 56 50 [2] 41 5b [2] 5a 15 [2] 67 }

  condition:
    any of them
}