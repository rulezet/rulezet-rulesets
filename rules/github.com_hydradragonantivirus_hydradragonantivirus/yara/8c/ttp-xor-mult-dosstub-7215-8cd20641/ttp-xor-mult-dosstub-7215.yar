rule TTP_XOR_MULT_DOSStub_7215 {
  strings:
    $key_7215 = { 26 7d [2] 52 65 [2] 15 67 [2] 52 76 [2] 1c 7a [2] 10 70 [2] 07 7b [2] 1c 35 [2] 21 }

  condition:
    any of them
}