rule TTP_XOR_MULT_DOSStub_507a {
  strings:
    $key_507a = { 04 12 [2] 70 0a [2] 37 08 [2] 70 19 [2] 3e 15 [2] 32 1f [2] 25 14 [2] 3e 5a [2] 03 }

  condition:
    any of them
}