rule TTP_XOR_MULT_DOSStub_0537 {
  strings:
    $key_0537 = { 51 5f [2] 25 47 [2] 62 45 [2] 25 54 [2] 6b 58 [2] 67 52 [2] 70 59 [2] 6b 17 [2] 56 }

  condition:
    any of them
}