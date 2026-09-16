rule TTP_XOR_MULT_DOSStub_412a {
  strings:
    $key_412a = { 15 42 [2] 61 5a [2] 26 58 [2] 61 49 [2] 2f 45 [2] 23 4f [2] 34 44 [2] 2f 0a [2] 12 }

  condition:
    any of them
}