rule TTP_XOR_MULT_DOSStub_526e {
  strings:
    $key_526e = { 06 06 [2] 72 1e [2] 35 1c [2] 72 0d [2] 3c 01 [2] 30 0b [2] 27 00 [2] 3c 4e [2] 01 }

  condition:
    any of them
}