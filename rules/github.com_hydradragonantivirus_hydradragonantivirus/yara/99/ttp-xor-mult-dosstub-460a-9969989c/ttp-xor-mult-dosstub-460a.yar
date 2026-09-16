rule TTP_XOR_MULT_DOSStub_460a {
  strings:
    $key_460a = { 12 62 [2] 66 7a [2] 21 78 [2] 66 69 [2] 28 65 [2] 24 6f [2] 33 64 [2] 28 2a [2] 15 }

  condition:
    any of them
}