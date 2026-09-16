rule TTP_XOR_MULT_DOSStub_5b6d {
  strings:
    $key_5b6d = { 0f 05 [2] 7b 1d [2] 3c 1f [2] 7b 0e [2] 35 02 [2] 39 08 [2] 2e 03 [2] 35 4d [2] 08 }

  condition:
    any of them
}