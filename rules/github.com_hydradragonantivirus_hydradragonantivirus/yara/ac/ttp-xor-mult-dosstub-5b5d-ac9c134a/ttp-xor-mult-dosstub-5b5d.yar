rule TTP_XOR_MULT_DOSStub_5b5d {
  strings:
    $key_5b5d = { 0f 35 [2] 7b 2d [2] 3c 2f [2] 7b 3e [2] 35 32 [2] 39 38 [2] 2e 33 [2] 35 7d [2] 08 }

  condition:
    any of them
}