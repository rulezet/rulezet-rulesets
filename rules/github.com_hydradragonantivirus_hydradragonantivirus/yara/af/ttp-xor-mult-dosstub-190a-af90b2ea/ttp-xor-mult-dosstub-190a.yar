rule TTP_XOR_MULT_DOSStub_190a {
  strings:
    $key_190a = { 4d 62 [2] 39 7a [2] 7e 78 [2] 39 69 [2] 77 65 [2] 7b 6f [2] 6c 64 [2] 77 2a [2] 4a }

  condition:
    any of them
}