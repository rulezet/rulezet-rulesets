rule TTP_XOR_MULT_DOSStub_0737 {
  strings:
    $key_0737 = { 53 5f [2] 27 47 [2] 60 45 [2] 27 54 [2] 69 58 [2] 65 52 [2] 72 59 [2] 69 17 [2] 54 }

  condition:
    any of them
}