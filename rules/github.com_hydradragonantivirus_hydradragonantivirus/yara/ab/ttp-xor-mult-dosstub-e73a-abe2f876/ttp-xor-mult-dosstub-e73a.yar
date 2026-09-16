rule TTP_XOR_MULT_DOSStub_e73a {
  strings:
    $key_e73a = { b3 52 [2] c7 4a [2] 80 48 [2] c7 59 [2] 89 55 [2] 85 5f [2] 92 54 [2] 89 1a [2] b4 }

  condition:
    any of them
}