rule TTP_XOR_MULT_DOSStub_176d {
  strings:
    $key_176d = { 43 05 [2] 37 1d [2] 70 1f [2] 37 0e [2] 79 02 [2] 75 08 [2] 62 03 [2] 79 4d [2] 44 }

  condition:
    any of them
}