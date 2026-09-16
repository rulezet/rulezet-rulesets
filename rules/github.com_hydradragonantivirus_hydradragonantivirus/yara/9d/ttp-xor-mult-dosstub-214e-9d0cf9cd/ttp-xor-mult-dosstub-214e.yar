rule TTP_XOR_MULT_DOSStub_214e {
  strings:
    $key_214e = { 75 26 [2] 01 3e [2] 46 3c [2] 01 2d [2] 4f 21 [2] 43 2b [2] 54 20 [2] 4f 6e [2] 72 }

  condition:
    any of them
}