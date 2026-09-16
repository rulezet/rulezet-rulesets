rule TTP_XOR_MULT_DOSStub_3337 {
  strings:
    $key_3337 = { 67 5f [2] 13 47 [2] 54 45 [2] 13 54 [2] 5d 58 [2] 51 52 [2] 46 59 [2] 5d 17 [2] 60 }

  condition:
    any of them
}