rule TTP_XOR_MULT_DOSStub_303a {
  strings:
    $key_303a = { 64 52 [2] 10 4a [2] 57 48 [2] 10 59 [2] 5e 55 [2] 52 5f [2] 45 54 [2] 5e 1a [2] 63 }

  condition:
    any of them
}