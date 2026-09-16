rule TTP_XOR_MULT_DOSStub_322a {
  strings:
    $key_322a = { 66 42 [2] 12 5a [2] 55 58 [2] 12 49 [2] 5c 45 [2] 50 4f [2] 47 44 [2] 5c 0a [2] 61 }

  condition:
    any of them
}