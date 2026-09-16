rule TTP_XOR_MULT_DOSStub_205d {
  strings:
    $key_205d = { 74 35 [2] 00 2d [2] 47 2f [2] 00 3e [2] 4e 32 [2] 42 38 [2] 55 33 [2] 4e 7d [2] 73 }

  condition:
    any of them
}