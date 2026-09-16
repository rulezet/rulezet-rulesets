rule TTP_XOR_MULT_DOSStub_014a {
  strings:
    $key_014a = { 55 22 [2] 21 3a [2] 66 38 [2] 21 29 [2] 6f 25 [2] 63 2f [2] 74 24 [2] 6f 6a [2] 52 }

  condition:
    any of them
}