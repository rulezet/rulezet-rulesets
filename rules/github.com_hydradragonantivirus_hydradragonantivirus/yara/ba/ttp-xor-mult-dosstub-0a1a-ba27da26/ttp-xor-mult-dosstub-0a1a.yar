rule TTP_XOR_MULT_DOSStub_0a1a {
  strings:
    $key_0a1a = { 5e 72 [2] 2a 6a [2] 6d 68 [2] 2a 79 [2] 64 75 [2] 68 7f [2] 7f 74 [2] 64 3a [2] 59 }

  condition:
    any of them
}