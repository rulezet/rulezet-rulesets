rule TTP_XOR_MULT_DOSStub_3e7d {
  strings:
    $key_3e7d = { 6a 15 [2] 1e 0d [2] 59 0f [2] 1e 1e [2] 50 12 [2] 5c 18 [2] 4b 13 [2] 50 5d [2] 6d }

  condition:
    any of them
}