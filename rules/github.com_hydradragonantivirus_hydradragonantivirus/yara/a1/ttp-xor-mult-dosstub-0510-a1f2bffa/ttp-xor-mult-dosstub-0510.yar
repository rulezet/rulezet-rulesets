rule TTP_XOR_MULT_DOSStub_0510 {
  strings:
    $key_0510 = { 51 78 [2] 25 60 [2] 62 62 [2] 25 73 [2] 6b 7f [2] 67 75 [2] 70 7e [2] 6b 30 [2] 56 }

  condition:
    any of them
}