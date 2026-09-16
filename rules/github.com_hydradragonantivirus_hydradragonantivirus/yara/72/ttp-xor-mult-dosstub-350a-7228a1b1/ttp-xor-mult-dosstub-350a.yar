rule TTP_XOR_MULT_DOSStub_350a {
  strings:
    $key_350a = { 61 62 [2] 15 7a [2] 52 78 [2] 15 69 [2] 5b 65 [2] 57 6f [2] 40 64 [2] 5b 2a [2] 66 }

  condition:
    any of them
}