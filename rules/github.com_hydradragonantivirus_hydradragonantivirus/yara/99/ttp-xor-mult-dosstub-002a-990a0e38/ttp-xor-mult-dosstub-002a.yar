rule TTP_XOR_MULT_DOSStub_002a {
  strings:
    $key_002a = { 54 42 [2] 20 5a [2] 67 58 [2] 20 49 [2] 6e 45 [2] 62 4f [2] 75 44 [2] 6e 0a [2] 53 }

  condition:
    any of them
}