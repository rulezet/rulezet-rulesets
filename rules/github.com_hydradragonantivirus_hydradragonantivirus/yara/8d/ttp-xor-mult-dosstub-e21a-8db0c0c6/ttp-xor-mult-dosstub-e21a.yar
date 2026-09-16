rule TTP_XOR_MULT_DOSStub_e21a {
  strings:
    $key_e21a = { b6 72 [2] c2 6a [2] 85 68 [2] c2 79 [2] 8c 75 [2] 80 7f [2] 97 74 [2] 8c 3a [2] b1 }

  condition:
    any of them
}