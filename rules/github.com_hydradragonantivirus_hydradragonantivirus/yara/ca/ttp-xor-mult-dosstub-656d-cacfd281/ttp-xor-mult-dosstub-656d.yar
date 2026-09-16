rule TTP_XOR_MULT_DOSStub_656d {
  strings:
    $key_656d = { 31 05 [2] 45 1d [2] 02 1f [2] 45 0e [2] 0b 02 [2] 07 08 [2] 10 03 [2] 0b 4d [2] 36 }

  condition:
    any of them
}