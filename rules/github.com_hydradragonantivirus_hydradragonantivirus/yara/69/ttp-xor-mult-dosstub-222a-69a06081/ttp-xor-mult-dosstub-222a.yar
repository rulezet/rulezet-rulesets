rule TTP_XOR_MULT_DOSStub_222a {
  strings:
    $key_222a = { 76 42 [2] 02 5a [2] 45 58 [2] 02 49 [2] 4c 45 [2] 40 4f [2] 57 44 [2] 4c 0a [2] 71 }

  condition:
    any of them
}