rule TTP_XOR_MULT_DOSStub_e77a {
  strings:
    $key_e77a = { b3 12 [2] c7 0a [2] 80 08 [2] c7 19 [2] 89 15 [2] 85 1f [2] 92 14 [2] 89 5a [2] b4 }

  condition:
    any of them
}