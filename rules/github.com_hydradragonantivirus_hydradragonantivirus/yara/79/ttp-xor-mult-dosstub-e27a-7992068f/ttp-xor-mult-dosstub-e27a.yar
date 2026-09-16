rule TTP_XOR_MULT_DOSStub_e27a {
  strings:
    $key_e27a = { b6 12 [2] c2 0a [2] 85 08 [2] c2 19 [2] 8c 15 [2] 80 1f [2] 97 14 [2] 8c 5a [2] b1 }

  condition:
    any of them
}