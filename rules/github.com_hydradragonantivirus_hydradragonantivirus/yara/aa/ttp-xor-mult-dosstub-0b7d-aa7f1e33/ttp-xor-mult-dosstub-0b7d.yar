rule TTP_XOR_MULT_DOSStub_0b7d {
  strings:
    $key_0b7d = { 5f 15 [2] 2b 0d [2] 6c 0f [2] 2b 1e [2] 65 12 [2] 69 18 [2] 7e 13 [2] 65 5d [2] 58 }

  condition:
    any of them
}