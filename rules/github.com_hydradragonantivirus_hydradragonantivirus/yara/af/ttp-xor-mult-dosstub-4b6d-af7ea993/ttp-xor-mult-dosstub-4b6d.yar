rule TTP_XOR_MULT_DOSStub_4b6d {
  strings:
    $key_4b6d = { 1f 05 [2] 6b 1d [2] 2c 1f [2] 6b 0e [2] 25 02 [2] 29 08 [2] 3e 03 [2] 25 4d [2] 18 }

  condition:
    any of them
}