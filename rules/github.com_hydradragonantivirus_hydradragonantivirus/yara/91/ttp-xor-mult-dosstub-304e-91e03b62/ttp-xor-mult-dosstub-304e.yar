rule TTP_XOR_MULT_DOSStub_304e {
  strings:
    $key_304e = { 64 26 [2] 10 3e [2] 57 3c [2] 10 2d [2] 5e 21 [2] 52 2b [2] 45 20 [2] 5e 6e [2] 63 }

  condition:
    any of them
}