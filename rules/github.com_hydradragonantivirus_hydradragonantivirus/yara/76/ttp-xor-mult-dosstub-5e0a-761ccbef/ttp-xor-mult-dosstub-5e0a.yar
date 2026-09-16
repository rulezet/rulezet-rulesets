rule TTP_XOR_MULT_DOSStub_5e0a {
  strings:
    $key_5e0a = { 0a 62 [2] 7e 7a [2] 39 78 [2] 7e 69 [2] 30 65 [2] 3c 6f [2] 2b 64 [2] 30 2a [2] 0d }

  condition:
    any of them
}