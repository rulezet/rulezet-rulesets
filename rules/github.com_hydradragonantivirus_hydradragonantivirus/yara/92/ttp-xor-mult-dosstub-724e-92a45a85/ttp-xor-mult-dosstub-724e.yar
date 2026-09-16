rule TTP_XOR_MULT_DOSStub_724e {
  strings:
    $key_724e = { 26 26 [2] 52 3e [2] 15 3c [2] 52 2d [2] 1c 21 [2] 10 2b [2] 07 20 [2] 1c 6e [2] 21 }

  condition:
    any of them
}