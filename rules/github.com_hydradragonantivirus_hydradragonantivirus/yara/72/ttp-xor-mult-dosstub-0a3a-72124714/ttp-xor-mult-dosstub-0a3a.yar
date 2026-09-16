rule TTP_XOR_MULT_DOSStub_0a3a {
  strings:
    $key_0a3a = { 5e 52 [2] 2a 4a [2] 6d 48 [2] 2a 59 [2] 64 55 [2] 68 5f [2] 7f 54 [2] 64 1a [2] 59 }

  condition:
    any of them
}