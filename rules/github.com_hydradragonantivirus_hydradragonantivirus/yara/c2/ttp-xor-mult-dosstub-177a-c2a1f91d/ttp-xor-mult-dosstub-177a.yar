rule TTP_XOR_MULT_DOSStub_177a {
  strings:
    $key_177a = { 43 12 [2] 37 0a [2] 70 08 [2] 37 19 [2] 79 15 [2] 75 1f [2] 62 14 [2] 79 5a [2] 44 }

  condition:
    any of them
}