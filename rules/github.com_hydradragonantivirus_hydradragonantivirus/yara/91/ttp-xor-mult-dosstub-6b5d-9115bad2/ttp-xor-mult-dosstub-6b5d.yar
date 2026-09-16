rule TTP_XOR_MULT_DOSStub_6b5d {
  strings:
    $key_6b5d = { 3f 35 [2] 4b 2d [2] 0c 2f [2] 4b 3e [2] 05 32 [2] 09 38 [2] 1e 33 [2] 05 7d [2] 38 }

  condition:
    any of them
}