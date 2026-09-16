rule TTP_XOR_MULT_DOSStub_6b2d {
  strings:
    $key_6b2d = { 3f 45 [2] 4b 5d [2] 0c 5f [2] 4b 4e [2] 05 42 [2] 09 48 [2] 1e 43 [2] 05 0d [2] 38 }

  condition:
    any of them
}