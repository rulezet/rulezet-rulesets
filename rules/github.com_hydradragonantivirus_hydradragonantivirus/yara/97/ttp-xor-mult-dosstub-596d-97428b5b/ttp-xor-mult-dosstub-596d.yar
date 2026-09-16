rule TTP_XOR_MULT_DOSStub_596d {
  strings:
    $key_596d = { 0d 05 [2] 79 1d [2] 3e 1f [2] 79 0e [2] 37 02 [2] 3b 08 [2] 2c 03 [2] 37 4d [2] 0a }

  condition:
    any of them
}