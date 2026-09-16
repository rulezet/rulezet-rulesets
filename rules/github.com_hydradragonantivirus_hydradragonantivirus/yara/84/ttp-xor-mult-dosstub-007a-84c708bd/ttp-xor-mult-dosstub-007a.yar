rule TTP_XOR_MULT_DOSStub_007a {
  strings:
    $key_007a = { 54 12 [2] 20 0a [2] 67 08 [2] 20 19 [2] 6e 15 [2] 62 1f [2] 75 14 [2] 6e 5a [2] 53 }

  condition:
    any of them
}