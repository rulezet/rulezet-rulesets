rule TTP_XOR_MULT_DOSStub_6b7d {
  strings:
    $key_6b7d = { 3f 15 [2] 4b 0d [2] 0c 0f [2] 4b 1e [2] 05 12 [2] 09 18 [2] 1e 13 [2] 05 5d [2] 38 }

  condition:
    any of them
}