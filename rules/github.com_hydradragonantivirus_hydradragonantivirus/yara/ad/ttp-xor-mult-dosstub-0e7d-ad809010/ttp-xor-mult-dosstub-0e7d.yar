rule TTP_XOR_MULT_DOSStub_0e7d {
  strings:
    $key_0e7d = { 5a 15 [2] 2e 0d [2] 69 0f [2] 2e 1e [2] 60 12 [2] 6c 18 [2] 7b 13 [2] 60 5d [2] 5d }

  condition:
    any of them
}