rule TTP_XOR_MULT_DOSStub_1e5a {
  strings:
    $key_1e5a = { 4a 32 [2] 3e 2a [2] 79 28 [2] 3e 39 [2] 70 35 [2] 7c 3f [2] 6b 34 [2] 70 7a [2] 4d }

  condition:
    any of them
}