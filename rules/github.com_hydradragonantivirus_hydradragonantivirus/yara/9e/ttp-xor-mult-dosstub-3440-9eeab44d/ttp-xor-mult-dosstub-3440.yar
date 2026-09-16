rule TTP_XOR_MULT_DOSStub_3440 {
  strings:
    $key_3440 = { 60 28 [2] 14 30 [2] 53 32 [2] 14 23 [2] 5a 2f [2] 56 25 [2] 41 2e [2] 5a 60 [2] 67 }

  condition:
    any of them
}