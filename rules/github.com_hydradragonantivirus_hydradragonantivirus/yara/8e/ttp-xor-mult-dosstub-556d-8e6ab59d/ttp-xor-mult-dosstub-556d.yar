rule TTP_XOR_MULT_DOSStub_556d {
  strings:
    $key_556d = { 01 05 [2] 75 1d [2] 32 1f [2] 75 0e [2] 3b 02 [2] 37 08 [2] 20 03 [2] 3b 4d [2] 06 }

  condition:
    any of them
}