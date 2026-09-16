rule TTP_XOR_MULT_DOSStub_5b7d {
  strings:
    $key_5b7d = { 0f 15 [2] 7b 0d [2] 3c 0f [2] 7b 1e [2] 35 12 [2] 39 18 [2] 2e 13 [2] 35 5d [2] 08 }

  condition:
    any of them
}