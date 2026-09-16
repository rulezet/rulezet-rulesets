rule TTP_XOR_MULT_DOSStub_127a {
  strings:
    $key_127a = { 46 12 [2] 32 0a [2] 75 08 [2] 32 19 [2] 7c 15 [2] 70 1f [2] 67 14 [2] 7c 5a [2] 41 }

  condition:
    any of them
}