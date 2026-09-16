rule TTP_XOR_MULT_DOSStub_454d {
  strings:
    $key_454d = { 11 25 [2] 65 3d [2] 22 3f [2] 65 2e [2] 2b 22 [2] 27 28 [2] 30 23 [2] 2b 6d [2] 16 }

  condition:
    any of them
}