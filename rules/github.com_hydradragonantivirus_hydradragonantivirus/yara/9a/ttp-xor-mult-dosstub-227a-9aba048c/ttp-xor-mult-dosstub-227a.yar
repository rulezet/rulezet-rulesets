rule TTP_XOR_MULT_DOSStub_227a {
  strings:
    $key_227a = { 76 12 [2] 02 0a [2] 45 08 [2] 02 19 [2] 4c 15 [2] 40 1f [2] 57 14 [2] 4c 5a [2] 71 }

  condition:
    any of them
}