rule TTP_XOR_MULT_DOSStub_5b4d {
  strings:
    $key_5b4d = { 0f 25 [2] 7b 3d [2] 3c 3f [2] 7b 2e [2] 35 22 [2] 39 28 [2] 2e 23 [2] 35 6d [2] 08 }

  condition:
    any of them
}