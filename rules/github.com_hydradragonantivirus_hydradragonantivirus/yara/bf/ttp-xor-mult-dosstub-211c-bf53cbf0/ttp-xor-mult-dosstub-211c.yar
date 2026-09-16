rule TTP_XOR_MULT_DOSStub_211c {
  strings:
    $key_211c = { 75 74 [2] 01 6c [2] 46 6e [2] 01 7f [2] 4f 73 [2] 43 79 [2] 54 72 [2] 4f 3c [2] 72 }

  condition:
    any of them
}