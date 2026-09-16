rule TTP_XOR_MULT_DOSStub_7b1d {
  strings:
    $key_7b1d = { 2f 75 [2] 5b 6d [2] 1c 6f [2] 5b 7e [2] 15 72 [2] 19 78 [2] 0e 73 [2] 15 3d [2] 28 }

  condition:
    any of them
}