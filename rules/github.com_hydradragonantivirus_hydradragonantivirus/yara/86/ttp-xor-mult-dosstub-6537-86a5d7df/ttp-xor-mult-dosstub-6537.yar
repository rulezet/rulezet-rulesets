rule TTP_XOR_MULT_DOSStub_6537 {
  strings:
    $key_6537 = { 31 5f [2] 45 47 [2] 02 45 [2] 45 54 [2] 0b 58 [2] 07 52 [2] 10 59 [2] 0b 17 [2] 36 }

  condition:
    any of them
}