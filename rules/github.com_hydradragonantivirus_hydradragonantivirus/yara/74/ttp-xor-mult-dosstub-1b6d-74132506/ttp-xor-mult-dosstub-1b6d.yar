rule TTP_XOR_MULT_DOSStub_1b6d {
  strings:
    $key_1b6d = { 4f 05 [2] 3b 1d [2] 7c 1f [2] 3b 0e [2] 75 02 [2] 79 08 [2] 6e 03 [2] 75 4d [2] 48 }

  condition:
    any of them
}