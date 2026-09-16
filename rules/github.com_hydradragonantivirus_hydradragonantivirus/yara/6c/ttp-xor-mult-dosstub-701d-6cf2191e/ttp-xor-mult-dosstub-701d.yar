rule TTP_XOR_MULT_DOSStub_701d {
  strings:
    $key_701d = { 24 75 [2] 50 6d [2] 17 6f [2] 50 7e [2] 1e 72 [2] 12 78 [2] 05 73 [2] 1e 3d [2] 23 }

  condition:
    any of them
}