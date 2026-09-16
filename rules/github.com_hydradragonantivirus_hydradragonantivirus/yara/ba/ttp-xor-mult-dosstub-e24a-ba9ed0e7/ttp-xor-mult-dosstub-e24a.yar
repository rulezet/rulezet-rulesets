rule TTP_XOR_MULT_DOSStub_e24a {
  strings:
    $key_e24a = { b6 22 [2] c2 3a [2] 85 38 [2] c2 29 [2] 8c 25 [2] 80 2f [2] 97 24 [2] 8c 6a [2] b1 }

  condition:
    any of them
}