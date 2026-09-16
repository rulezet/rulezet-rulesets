rule TTP_XOR_MULT_DOSStub_2e7d {
  strings:
    $key_2e7d = { 7a 15 [2] 0e 0d [2] 49 0f [2] 0e 1e [2] 40 12 [2] 4c 18 [2] 5b 13 [2] 40 5d [2] 7d }

  condition:
    any of them
}