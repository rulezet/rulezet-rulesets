rule TTP_XOR_MULT_DOSStub_2637 {
  strings:
    $key_2637 = { 72 5f [2] 06 47 [2] 41 45 [2] 06 54 [2] 48 58 [2] 44 52 [2] 53 59 [2] 48 17 [2] 75 }

  condition:
    any of them
}