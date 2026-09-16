rule TTP_XOR_MULT_DOSStub_607d {
  strings:
    $key_607d = { 34 15 [2] 40 0d [2] 07 0f [2] 40 1e [2] 0e 12 [2] 02 18 [2] 15 13 [2] 0e 5d [2] 33 }

  condition:
    any of them
}