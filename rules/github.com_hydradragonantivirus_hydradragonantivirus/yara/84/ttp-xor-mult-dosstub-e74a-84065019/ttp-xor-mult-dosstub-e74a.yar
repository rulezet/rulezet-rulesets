rule TTP_XOR_MULT_DOSStub_e74a {
  strings:
    $key_e74a = { b3 22 [2] c7 3a [2] 80 38 [2] c7 29 [2] 89 25 [2] 85 2f [2] 92 24 [2] 89 6a [2] b4 }

  condition:
    any of them
}