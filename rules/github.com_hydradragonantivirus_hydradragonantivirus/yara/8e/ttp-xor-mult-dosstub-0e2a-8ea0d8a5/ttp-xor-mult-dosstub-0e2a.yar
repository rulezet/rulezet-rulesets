rule TTP_XOR_MULT_DOSStub_0e2a {
  strings:
    $key_0e2a = { 5a 42 [2] 2e 5a [2] 69 58 [2] 2e 49 [2] 60 45 [2] 6c 4f [2] 7b 44 [2] 60 0a [2] 5d }

  condition:
    any of them
}