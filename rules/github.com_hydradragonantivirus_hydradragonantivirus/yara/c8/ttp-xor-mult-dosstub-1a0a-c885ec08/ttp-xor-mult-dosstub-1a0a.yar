rule TTP_XOR_MULT_DOSStub_1a0a {
  strings:
    $key_1a0a = { 4e 62 [2] 3a 7a [2] 7d 78 [2] 3a 69 [2] 74 65 [2] 78 6f [2] 6f 64 [2] 74 2a [2] 49 }

  condition:
    any of them
}