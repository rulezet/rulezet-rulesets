rule TTP_XOR_MULT_DOSStub_4a2a {
  strings:
    $key_4a2a = { 1e 42 [2] 6a 5a [2] 2d 58 [2] 6a 49 [2] 24 45 [2] 28 4f [2] 3f 44 [2] 24 0a [2] 19 }

  condition:
    any of them
}