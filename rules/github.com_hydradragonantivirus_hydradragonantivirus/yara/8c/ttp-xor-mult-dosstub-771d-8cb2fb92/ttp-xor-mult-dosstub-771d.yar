rule TTP_XOR_MULT_DOSStub_771d {
  strings:
    $key_771d = { 23 75 [2] 57 6d [2] 10 6f [2] 57 7e [2] 19 72 [2] 15 78 [2] 02 73 [2] 19 3d [2] 24 }

  condition:
    any of them
}