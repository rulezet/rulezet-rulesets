rule TTP_XOR_MULT_DOSStub_1e2a {
  strings:
    $key_1e2a = { 4a 42 [2] 3e 5a [2] 79 58 [2] 3e 49 [2] 70 45 [2] 7c 4f [2] 6b 44 [2] 70 0a [2] 4d }

  condition:
    any of them
}