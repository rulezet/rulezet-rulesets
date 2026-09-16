rule TTP_XOR_MULT_DOSStub_2e2a {
  strings:
    $key_2e2a = { 7a 42 [2] 0e 5a [2] 49 58 [2] 0e 49 [2] 40 45 [2] 4c 4f [2] 5b 44 [2] 40 0a [2] 7d }

  condition:
    any of them
}