rule TTP_XOR_MULT_DOSStub_324e {
  strings:
    $key_324e = { 66 26 [2] 12 3e [2] 55 3c [2] 12 2d [2] 5c 21 [2] 50 2b [2] 47 20 [2] 5c 6e [2] 61 }

  condition:
    any of them
}