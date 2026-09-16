rule TTP_XOR_MULT_DOSStub_332a {
  strings:
    $key_332a = { 67 42 [2] 13 5a [2] 54 58 [2] 13 49 [2] 5d 45 [2] 51 4f [2] 46 44 [2] 5d 0a [2] 60 }

  condition:
    any of them
}