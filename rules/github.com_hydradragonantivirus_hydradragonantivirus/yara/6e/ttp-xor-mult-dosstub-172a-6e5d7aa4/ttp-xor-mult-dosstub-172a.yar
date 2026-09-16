rule TTP_XOR_MULT_DOSStub_172a {
  strings:
    $key_172a = { 43 42 [2] 37 5a [2] 70 58 [2] 37 49 [2] 79 45 [2] 75 4f [2] 62 44 [2] 79 0a [2] 44 }

  condition:
    any of them
}