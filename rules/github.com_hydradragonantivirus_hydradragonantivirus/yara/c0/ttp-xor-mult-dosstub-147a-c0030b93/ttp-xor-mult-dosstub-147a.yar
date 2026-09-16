rule TTP_XOR_MULT_DOSStub_147a {
  strings:
    $key_147a = { 40 12 [2] 34 0a [2] 73 08 [2] 34 19 [2] 7a 15 [2] 76 1f [2] 61 14 [2] 7a 5a [2] 47 }

  condition:
    any of them
}