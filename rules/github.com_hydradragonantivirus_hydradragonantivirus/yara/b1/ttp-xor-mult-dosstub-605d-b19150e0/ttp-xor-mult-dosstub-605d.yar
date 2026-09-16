rule TTP_XOR_MULT_DOSStub_605d {
  strings:
    $key_605d = { 34 35 [2] 40 2d [2] 07 2f [2] 40 3e [2] 0e 32 [2] 02 38 [2] 15 33 [2] 0e 7d [2] 33 }

  condition:
    any of them
}